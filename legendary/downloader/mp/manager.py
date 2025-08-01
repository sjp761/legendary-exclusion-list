# coding: utf-8

# please don't look at this code too hard, it's a mess.

from fnmatch import fnmatch
import logging
import os
import time

from collections import Counter, defaultdict, deque
from logging.handlers import QueueHandler
from multiprocessing import cpu_count, Process, Queue as MPQueue
from multiprocessing.shared_memory import SharedMemory
from queue import Empty
from sys import exit
from threading import Condition, Thread

from legendary.downloader.mp.workers import DLWorker, FileWorker
from legendary.models.downloading import *
from legendary.models.manifest import ManifestComparison, Manifest


class DLManager(Process):
    def __init__(self, download_dir, base_url, cache_dir=None, status_q=None,
                 max_workers=0, update_interval=1.0, dl_timeout=10, resume_file=None,
                 max_shared_memory=1024 * 1024 * 1024, bind_ip=None):
        super().__init__(name='DLManager')
        self.log = logging.getLogger('DLM')
        self.proc_debug = False

        self.base_url = base_url
        self.dl_dir = download_dir
        self.cache_dir = cache_dir or os.path.join(download_dir, '.cache')

        # All the queues!
        self.logging_queue = None
        self.dl_worker_queue = None
        self.writer_queue = None
        self.dl_result_q = None
        self.writer_result_q = None

        # Worker stuff
        self.max_workers = max_workers or min(cpu_count() * 2, 16)
        self.dl_timeout = dl_timeout
        self.bind_ips = [] if not bind_ip else bind_ip.split(',')

        # Analysis stuff
        self.analysis = None
        self.tasks = deque()
        self.chunks_to_dl = deque()
        self.chunk_data_list = None

        # shared memory stuff
        self.max_shared_memory = max_shared_memory  # 1 GiB by default
        self.sms = deque()
        self.shared_memory = None

        # Interval for log updates and pushing updates to the queue
        self.update_interval = update_interval
        self.status_queue = status_q  # queue used to relay status info back to GUI/CLI

        # Resume file stuff
        self.resume_file = resume_file
        self.hash_map = dict()

        # cross-thread runtime information
        self.running = True
        self.active_tasks = 0
        self.children = []
        self.threads = []
        self.conditions = []
        # bytes downloaded and decompressed since last report
        self.bytes_downloaded_since_last = 0
        self.bytes_decompressed_since_last = 0
        # bytes written since last report
        self.bytes_written_since_last = 0
        # bytes read since last report
        self.bytes_read_since_last = 0
        # chunks written since last report
        self.num_processed_since_last = 0
        self.num_tasks_processed_since_last = 0

    def matches(self, file, excludelist):
        for pattern in excludelist:
            if '/' in file and not pattern.endswith('*') and not pattern.startswith('*'):
                if os.path.dirname(file) == os.path.dirname(pattern) and fnmatch(os.path.basename(file), os.path.basename(pattern)):
                    return True
            else:
                if fnmatch(file, pattern):
                    return True
        return False

    def run_analysis(self, manifest: Manifest, old_manifest: Manifest = None,
                     patch=True, resume=True, file_prefix_filter=None,
                     file_exclude_filter=None, file_exclude_configured=None,
                     file_install_tag=None,
                     read_files=False,
                     processing_optimization=False) -> AnalysisResult:
        """
        Run analysis on manifest and old manifest (if not None) and return a result
        with a summary resources required in order to install the provided manifest.

        :param manifest: Manifest to install
        :param old_manifest: Old manifest to patch from (if applicable)
        :param patch: Patch instead of redownloading the entire file
        :param resume: Continue based on resume file if it exists
        :param file_prefix_filter: Only download files that start with this prefix
        :param file_exclude_filter: Exclude files with this prefix from download
        :param file_exclude_configured: Exclude files based on configured patterns
        :param file_install_tag: Only install files with the specified tag
        :param read_files: Allow reading from already finished files
        :param processing_optimization: Attempt to optimize processing order and RAM usage
        :return: AnalysisResult
        """

        analysis_res = AnalysisResult()
        analysis_res.install_size = sum(fm.file_size for fm in manifest.file_manifest_list.elements)
        analysis_res.biggest_chunk = max(c.window_size for c in manifest.chunk_data_list.elements)
        analysis_res.biggest_file_size = max(f.file_size for f in manifest.file_manifest_list.elements)
        is_1mib = analysis_res.biggest_chunk == 1024 * 1024
        self.log.debug(f'Biggest chunk size: {analysis_res.biggest_chunk} bytes (== 1 MiB? {is_1mib})')

        self.log.debug(f'Creating manifest comparison...')
        mc = ManifestComparison.create(manifest, old_manifest)
        analysis_res.manifest_comparison = mc

        if resume and self.resume_file and os.path.exists(self.resume_file):
            self.log.info('Found previously interrupted download. Download will be resumed if possible.')
            try:
                missing = 0
                mismatch = 0
                completed_files = set()

                for line in open(self.resume_file, encoding='utf-8').readlines():
                    file_hash, _, filename = line.strip().partition(':')
                    _p = os.path.join(self.dl_dir, filename)
                    if not os.path.exists(_p):
                        self.log.debug(f'File does not exist but is in resume file: "{_p}"')
                        missing += 1
                    elif file_hash != manifest.file_manifest_list.get_file_by_path(filename).sha_hash.hex():
                        mismatch += 1
                    else:
                        completed_files.add(filename)

                if missing:
                    self.log.warning(f'{missing} previously completed file(s) are missing, they will be redownloaded.')
                if mismatch:
                    self.log.warning(f'{mismatch} existing file(s) have been changed and will be redownloaded.')

                # remove completed files from changed/added and move them to unchanged for the analysis.
                mc.added -= completed_files
                mc.changed -= completed_files
                mc.unchanged |= completed_files
                self.log.info(f'Skipping {len(completed_files)} files based on resume data.')
            except Exception as e:
                self.log.warning(f'Reading resume file failed: {e!r}, continuing as normal...')

        elif resume:
            # Basic check if files exist locally, put all missing files into "added"
            # This allows new SDL tags to be installed without having to do a repair as well.
            missing_files = set()

            for fm in manifest.file_manifest_list.elements:
                if fm.filename in mc.added:
                    continue

                local_path = os.path.join(self.dl_dir, fm.filename)
                if not os.path.exists(local_path):
                    missing_files.add(fm.filename)

            self.log.info(f'Found {len(missing_files)} missing files.')
            mc.added |= missing_files
            mc.changed -= missing_files
            mc.unchanged -= missing_files

        # Install tags are used for selective downloading, e.g. for language packs
        additional_deletion_tasks = []
        if file_install_tag is not None:
            if isinstance(file_install_tag, str):
                file_install_tag = [file_install_tag]

            files_to_skip = set(i.filename for i in manifest.file_manifest_list.elements
                                if not any((fit in i.install_tags) or (not fit and not i.install_tags)
                                           for fit in file_install_tag))
            self.log.info(f'Found {len(files_to_skip)} files to skip based on install tag.')
            mc.added -= files_to_skip
            mc.changed -= files_to_skip
            mc.unchanged |= files_to_skip
            for fname in sorted(files_to_skip):
                additional_deletion_tasks.append(FileTask(fname, flags=TaskFlags.DELETE_FILE | TaskFlags.SILENT))

        # if include/exclude prefix has been set: mark all files that are not to be downloaded as unchanged
        if file_exclude_filter:
            if isinstance(file_exclude_filter, str):
                file_exclude_filter = [file_exclude_filter]

            file_exclude_filter = [f.lower() for f in file_exclude_filter]
            files_to_skip = set(i.filename for i in manifest.file_manifest_list.elements if
                                any(i.filename.lower().startswith(pfx) for pfx in file_exclude_filter))
            self.log.info(f'Found {len(files_to_skip)} files to skip based on exclude prefix.')
            mc.added -= files_to_skip
            mc.changed -= files_to_skip
            mc.unchanged |= files_to_skip

        if file_exclude_configured:
            if isinstance(file_exclude_configured, str):
                file_exclude_configured = [file_exclude_configured]
            file_exclude_configured = [f.lower() for f in file_exclude_configured]
            files_to_skip = set(i.filename for i in manifest.file_manifest_list.elements if self.matches(i.filename.lower(), file_exclude_configured))
            mc.added -= files_to_skip
            mc.changed -= files_to_skip
            mc.unchanged |= files_to_skip

        if file_prefix_filter:
            if isinstance(file_prefix_filter, str):
                file_prefix_filter = [file_prefix_filter]

            file_prefix_filter = [f.lower() for f in file_prefix_filter]
            files_to_skip = set(i.filename for i in manifest.file_manifest_list.elements if not
                                any(i.filename.lower().startswith(pfx) for pfx in file_prefix_filter))
            self.log.info(f'Found {len(files_to_skip)} files to skip based on include prefix(es)')
            mc.added -= files_to_skip
            mc.changed -= files_to_skip
            mc.unchanged |= files_to_skip

        if file_prefix_filter or file_exclude_filter or file_install_tag:
            self.log.info(f'Remaining files after filtering: {len(mc.added) + len(mc.changed)}')
            # correct install size after filtering
            analysis_res.install_size = sum(fm.file_size for fm in manifest.file_manifest_list.elements
                                            if fm.filename in mc.added)

        if mc.removed:
            analysis_res.removed = len(mc.removed)
            self.log.debug(f'{analysis_res.removed} removed files')
        if mc.added:
            analysis_res.added = len(mc.added)
            self.log.debug(f'{analysis_res.added} added files')
        if mc.changed:
            analysis_res.changed = len(mc.changed)
            self.log.debug(f'{analysis_res.changed} changed files')
        if mc.unchanged:
            analysis_res.unchanged = len(mc.unchanged)
            self.log.debug(f'{analysis_res.unchanged} unchanged files')

        if processing_optimization and len(manifest.file_manifest_list.elements) > 100_000:
            self.log.warning('Manifest contains too many files, processing optimizations will be disabled.')
            processing_optimization = False
        elif processing_optimization:
            self.log.info('Processing order optimization is enabled, analysis may take a few seconds longer...')

        # count references to chunks for determining runtime cache size later
        references = Counter()
        fmlist = sorted(manifest.file_manifest_list.elements,
                        key=lambda a: a.filename.lower())

        # Create reference count for chunks and calculate additional/temporary disk size required for install
        current_tmp_size = 0
        for fm in fmlist:
            self.hash_map[fm.filename] = fm.sha_hash.hex()

            # chunks of unchanged files are not downloaded so we can skip them
            if fm.filename in mc.unchanged:
                analysis_res.unchanged += fm.file_size
                continue

            for cp in fm.chunk_parts:
                references[cp.guid_num] += 1

            if fm.filename in mc.added:
                # if the file was added, it just adds to the delta
                current_tmp_size += fm.file_size
                analysis_res.disk_space_delta = max(current_tmp_size, analysis_res.disk_space_delta)
            elif fm.filename in mc.changed:
                # if the file was changed, we need temporary space equal to the full size,
                # but then subtract the size of the old file as it's deleted on write completion.
                current_tmp_size += fm.file_size
                analysis_res.disk_space_delta = max(current_tmp_size, analysis_res.disk_space_delta)
                current_tmp_size -= old_manifest.file_manifest_list.get_file_by_path(fm.filename).file_size

        # clamp to 0
        self.log.debug(f'Disk space delta: {analysis_res.disk_space_delta/1024/1024:.02f} MiB')

        if processing_optimization:
            s_time = time.time()
            # reorder the file manifest list to group files that share many chunks
            # 4 is mostly arbitrary but has shown in testing to be a good choice
            min_overlap = 4
            # ignore files with less than N chunk parts, this speeds things up dramatically
            cp_threshold = 5

            remaining_files = {fm.filename: {cp.guid_num for cp in fm.chunk_parts}
                               for fm in fmlist if fm.filename not in mc.unchanged}
            _fmlist = []

            # iterate over all files that will be downloaded and pair up those that share the most chunks
            for fm in fmlist:
                if fm.filename not in remaining_files:
                    continue

                _fmlist.append(fm)
                f_chunks = remaining_files.pop(fm.filename)
                if len(f_chunks) < cp_threshold:
                    continue

                best_overlap, match = 0, None
                for fname, chunks in remaining_files.items():
                    if len(chunks) < cp_threshold:
                        continue
                    overlap = len(f_chunks & chunks)
                    if overlap > min_overlap and overlap > best_overlap:
                        best_overlap, match = overlap, fname

                if match:
                    _fmlist.append(manifest.file_manifest_list.get_file_by_path(match))
                    remaining_files.pop(match)

            fmlist = _fmlist
            opt_delta = time.time() - s_time
            self.log.debug(f'Processing optimizations took {opt_delta:.01f} seconds.')

        # determine reusable chunks and prepare lookup table for reusable ones
        re_usable = defaultdict(dict)
        if old_manifest and mc.changed and patch:
            self.log.debug('Analyzing manifests for re-usable chunks...')
            for changed in mc.changed:
                old_file = old_manifest.file_manifest_list.get_file_by_path(changed)
                new_file = manifest.file_manifest_list.get_file_by_path(changed)

                existing_chunks = defaultdict(list)
                off = 0
                for cp in old_file.chunk_parts:
                    existing_chunks[cp.guid_num].append((off, cp.offset, cp.offset + cp.size))
                    off += cp.size

                for cp in new_file.chunk_parts:
                    key = (cp.guid_num, cp.offset, cp.size)
                    for file_o, cp_o, cp_end_o in existing_chunks[cp.guid_num]:
                        # check if new chunk part is wholly contained in the old chunk part
                        if cp_o <= cp.offset and (cp.offset + cp.size) <= cp_end_o:
                            references[cp.guid_num] -= 1
                            re_usable[changed][key] = file_o + (cp.offset - cp_o)
                            analysis_res.reuse_size += cp.size
                            break

        # determine whether a chunk part is currently in written files
        reusable_written = defaultdict(dict)
        if read_files:
            self.log.debug('Analyzing manifest for re-usable chunks in saved files...')
            cur_written_cps = defaultdict(list)
            for cur_file in fmlist:
                cur_file_cps = dict()
                cur_file_offset = 0
                for cp in cur_file.chunk_parts:
                    key = (cp.guid_num, cp.offset, cp.size)
                    for wr_file_name, wr_file_offset, wr_cp_offset, wr_cp_end_offset in cur_written_cps[cp.guid_num]:
                        # check if new chunk part is wholly contained in a written chunk part
                        cur_cp_end_offset = cp.offset + cp.size
                        if wr_cp_offset <= cp.offset and wr_cp_end_offset >= cur_cp_end_offset:
                            references[cp.guid_num] -= 1
                            reuse_offset = wr_file_offset + (cp.offset - wr_cp_offset)
                            reusable_written[cur_file.filename][key] = (wr_file_name, reuse_offset)
                            break
                    cur_file_cps[cp.guid_num] = (cur_file.filename, cur_file_offset, cp.offset, cp.offset + cp.size)
                    cur_file_offset += cp.size

                for guid, value in cur_file_cps.items():
                    cur_written_cps[guid].append(value)

        last_cache_size = current_cache_size = 0
        # set to determine whether a file is currently cached or not
        cached = set()
        # Using this secondary set is orders of magnitude faster than checking the deque.
        chunks_in_dl_list = set()
        # This is just used to count all unique guids that have been cached
        dl_cache_guids = set()

        # run through the list of files and create the download jobs and also determine minimum
        # runtime cache requirement by simulating adding/removing from cache during download.
        self.log.debug('Creating filetasks and chunktasks...')
        for current_file in fmlist:
            # skip unchanged and empty files
            if current_file.filename in mc.unchanged:
                continue
            elif not current_file.chunk_parts:
                self.tasks.append(FileTask(current_file.filename, flags=TaskFlags.CREATE_EMPTY_FILE))
                continue

            existing_chunks = re_usable.get(current_file.filename, None)
            written_chunks = reusable_written.get(current_file.filename, None)
            chunk_tasks = []
            reused = 0

            for cp in current_file.chunk_parts:
                ct = ChunkTask(cp.guid_num, cp.offset, cp.size)

                # re-use the chunk from the existing file if we can
                key = (cp.guid_num, cp.offset, cp.size)
                if existing_chunks and key in existing_chunks:
                    reused += 1
                    ct.chunk_file = current_file.filename
                    ct.chunk_offset = existing_chunks[key]
                elif written_chunks and key in written_chunks:
                    ct.chunk_file, ct.chunk_offset = written_chunks[key]
                else:
                    # add to DL list if not already in it
                    if cp.guid_num not in chunks_in_dl_list:
                        self.chunks_to_dl.append(cp.guid_num)
                        chunks_in_dl_list.add(cp.guid_num)

                    # if chunk has more than one use or is already in cache,
                    # check if we need to add or remove it again.
                    if references[cp.guid_num] > 1 or cp.guid_num in cached:
                        references[cp.guid_num] -= 1

                        # delete from cache if no references left
                        if references[cp.guid_num] < 1:
                            current_cache_size -= analysis_res.biggest_chunk
                            cached.remove(cp.guid_num)
                            ct.cleanup = True
                        # add to cache if not already cached
                        elif cp.guid_num not in cached:
                            dl_cache_guids.add(cp.guid_num)
                            cached.add(cp.guid_num)
                            current_cache_size += analysis_res.biggest_chunk
                    else:
                        ct.cleanup = True

                chunk_tasks.append(ct)

            if reused:
                self.log.debug(f' + Reusing {reused} chunks from: {current_file.filename}')
                # open temporary file that will contain download + old file contents
                self.tasks.append(FileTask(current_file.filename + u'.tmp', flags=TaskFlags.OPEN_FILE))
                self.tasks.extend(chunk_tasks)
                self.tasks.append(FileTask(current_file.filename + u'.tmp', flags=TaskFlags.CLOSE_FILE))
                # delete old file and rename temporary
                self.tasks.append(FileTask(current_file.filename, old_file=current_file.filename + u'.tmp',
                                           flags=TaskFlags.RENAME_FILE | TaskFlags.DELETE_FILE))
            else:
                self.tasks.append(FileTask(current_file.filename, flags=TaskFlags.OPEN_FILE))
                self.tasks.extend(chunk_tasks)
                self.tasks.append(FileTask(current_file.filename, flags=TaskFlags.CLOSE_FILE))

            if current_file.executable:
                self.tasks.append(FileTask(current_file.filename, flags=TaskFlags.MAKE_EXECUTABLE))

            # check if runtime cache size has changed
            if current_cache_size > last_cache_size:
                self.log.debug(f' * New maximum cache size: {current_cache_size / 1024 / 1024:.02f} MiB')
                last_cache_size = current_cache_size

        self.log.debug(f'Final cache size requirement: {last_cache_size / 1024 / 1024} MiB.')
        analysis_res.min_memory = last_cache_size + (1024 * 1024 * 32)  # add some padding just to be safe

        # Todo implement on-disk caching to avoid this issue.
        if analysis_res.min_memory > self.max_shared_memory:
            shared_mib = f'{self.max_shared_memory / 1024 / 1024:.01f} MiB'
            required_mib = f'{analysis_res.min_memory / 1024 / 1024:.01f} MiB'
            suggested_mib = round(self.max_shared_memory / 1024 / 1024 +
                                  (analysis_res.min_memory - self.max_shared_memory) / 1024 / 1024 + 32)

            if processing_optimization:
                message = f'Try running legendary with "--enable-reordering --max-shared-memory {suggested_mib:.0f}"'
            else:
                message = 'Try running legendary with "--enable-reordering" to reduce memory usage, ' \
                          f'or use "--max-shared-memory {suggested_mib:.0f}" to increase the limit.'

            raise MemoryError(f'Current shared memory cache is smaller than required: {shared_mib} < {required_mib}. '
                              + message)

        # calculate actual dl and patch write size.
        analysis_res.dl_size = \
            sum(c.file_size for c in manifest.chunk_data_list.elements if c.guid_num in chunks_in_dl_list)
        analysis_res.uncompressed_dl_size = \
            sum(c.window_size for c in manifest.chunk_data_list.elements if c.guid_num in chunks_in_dl_list)

        # add jobs to remove files
        for fname in mc.removed:
            self.tasks.append(FileTask(fname, flags=TaskFlags.DELETE_FILE))
        self.tasks.extend(additional_deletion_tasks)

        analysis_res.num_chunks_cache = len(dl_cache_guids)
        self.chunk_data_list = manifest.chunk_data_list
        self.analysis = analysis_res

        return analysis_res

    def download_job_manager(self, task_cond: Condition, shm_cond: Condition):
        while self.chunks_to_dl and self.running:
            while self.active_tasks < self.max_workers * 2 and self.chunks_to_dl:
                try:
                    sms = self.sms.popleft()
                    no_shm = False
                except IndexError:  # no free cache
                    no_shm = True
                    break

                c_guid = self.chunks_to_dl.popleft()
                chunk = self.chunk_data_list.get_chunk_by_guid(c_guid)
                self.log.debug(f'Adding {chunk.guid_num} (active: {self.active_tasks})')
                try:
                    self.dl_worker_queue.put(DownloaderTask(url=self.base_url + '/' + chunk.path,
                                                            chunk_guid=c_guid, shm=sms),
                                             timeout=1.0)
                except Exception as e:
                    self.log.warning(f'Failed to add to download queue: {e!r}')
                    self.chunks_to_dl.appendleft(c_guid)
                    break

                self.active_tasks += 1
            else:
                # active tasks limit hit, wait for tasks to finish
                with task_cond:
                    self.log.debug('Waiting for download tasks to complete..')
                    task_cond.wait(timeout=1.0)
                    continue

            if no_shm:
                # if we break we ran out of shared memory, so wait for that.
                with shm_cond:
                    self.log.debug('Waiting for more shared memory...')
                    shm_cond.wait(timeout=1.0)

        self.log.debug('Download Job Manager quitting...')

    def dl_results_handler(self, task_cond: Condition):
        in_buffer = dict()

        task = self.tasks.popleft()
        current_file = ''

        while task and self.running:
            if isinstance(task, FileTask):  # this wasn't necessarily a good idea...
                try:
                    self.writer_queue.put(WriterTask(**task.__dict__), timeout=1.0)
                    if task.flags & TaskFlags.OPEN_FILE:
                        current_file = task.filename
                except Exception as e:
                    self.tasks.appendleft(task)
                    self.log.warning(f'Adding to queue failed: {e!r}')
                    continue

                try:
                    task = self.tasks.popleft()
                except IndexError:  # finished
                    break
                continue

            while (task.chunk_guid in in_buffer) or task.chunk_file:
                res_shm = None
                if not task.chunk_file:  # not re-using from an old file
                    res_shm = in_buffer[task.chunk_guid].shm

                try:
                    self.log.debug(f'Adding {task.chunk_guid} to writer queue')
                    self.writer_queue.put(WriterTask(
                        filename=current_file, shared_memory=res_shm,
                        chunk_offset=task.chunk_offset, chunk_size=task.chunk_size,
                        chunk_guid=task.chunk_guid, old_file=task.chunk_file,
                        flags=TaskFlags.RELEASE_MEMORY if task.cleanup else TaskFlags.NONE
                    ), timeout=1.0)
                except Exception as e:
                    self.log.warning(f'Adding to queue failed: {e!r}')
                    break

                if task.cleanup and not task.chunk_file:
                    del in_buffer[task.chunk_guid]

                try:
                    task = self.tasks.popleft()
                    if isinstance(task, FileTask):
                        break
                except IndexError:  # finished
                    task = None
                    break
            else:  # only enter blocking code if the loop did not break
                try:
                    res = self.dl_result_q.get(timeout=1)
                    self.active_tasks -= 1
                    with task_cond:
                        task_cond.notify()

                    if res.success:
                        self.log.debug(f'Download for {res.chunk_guid} succeeded, adding to in_buffer...')
                        in_buffer[res.chunk_guid] = res
                        self.bytes_downloaded_since_last += res.size_downloaded
                        self.bytes_decompressed_since_last += res.size_decompressed
                    else:
                        self.log.error(f'Download for {res.chunk_guid} failed, retrying...')
                        try:
                            # since the result is a subclass of the task we can simply resubmit the result object
                            self.dl_worker_queue.put(res, timeout=1.0)
                            self.active_tasks += 1
                        except Exception as e:
                            self.log.warning(f'Failed adding retry task to queue! {e!r}')
                            # If this failed for whatever reason, put the chunk at the front of the DL list
                            self.chunks_to_dl.appendleft(res.chunk_guid)
                except Empty:
                    pass
                except Exception as e:
                    self.log.warning(f'Unhandled exception when trying to read download result queue: {e!r}')

        self.log.debug('Download result handler quitting...')

    def fw_results_handler(self, shm_cond: Condition):
        while self.running:
            try:
                res = self.writer_result_q.get(timeout=1.0)

                if isinstance(res, TerminateWorkerTask):
                    self.log.debug('Got termination command in FW result handler')
                    break

                self.num_tasks_processed_since_last += 1

                if res.flags & TaskFlags.CLOSE_FILE and self.resume_file and res.success:
                    if res.filename.endswith('.tmp'):
                        res.filename = res.filename[:-4]

                    file_hash = self.hash_map[res.filename]
                    # write last completed file to super simple resume file
                    with open(self.resume_file, 'a', encoding='utf-8') as rf:
                        rf.write(f'{file_hash}:{res.filename}\n')

                if not res.success:
                    # todo make this kill the installation process or at least skip the file and mark it as failed
                    self.log.fatal(f'Writing for {res.filename} failed!')
                if res.flags & TaskFlags.RELEASE_MEMORY:
                    self.sms.appendleft(res.shared_memory)
                    with shm_cond:
                        shm_cond.notify()

                if res.chunk_guid:
                    self.bytes_written_since_last += res.size
                    # if there's no shared memory we must have read from disk.
                    if not res.shared_memory:
                        self.bytes_read_since_last += res.size
                    self.num_processed_since_last += 1

            except Empty:
                continue
            except Exception as e:
                self.log.warning(f'Exception when trying to read writer result queue: {e!r}')
        self.log.debug('Writer result handler quitting...')

    def run(self):
        if not self.analysis:
            raise ValueError('Did not run analysis before trying to run download!')

        # Subprocess will use its own root logger that logs to a Queue instead
        _root = logging.getLogger()
        _root.setLevel(logging.DEBUG if self.proc_debug else logging.INFO)
        if self.logging_queue:
            _root.handlers = []
            _root.addHandler(QueueHandler(self.logging_queue))

        self.log = logging.getLogger('DLManager')
        self.log.info(f'Download Manager running with process-id: {os.getpid()}')

        try:
            self.run_real()
        except KeyboardInterrupt:
            self.log.warning('Immediate exit requested!')
            self.running = False

            # send conditions to unlock threads if they aren't already
            for cond in self.conditions:
                with cond:
                    cond.notify()

            # make sure threads are dead.
            for t in self.threads:
                t.join(timeout=5.0)
                if t.is_alive():
                    self.log.warning(f'Thread did not terminate! {repr(t)}')

            # forcibly kill DL workers that are not actually dead yet
            for child in self.children:
                child.join(timeout=5.0)
                if child.exitcode is None:
                    child.terminate()

            # clean up all the queues, otherwise this process won't terminate properly
            for name, q in zip(('Download jobs', 'Writer jobs', 'Download results', 'Writer results'),
                               (self.dl_worker_queue, self.writer_queue, self.dl_result_q, self.writer_result_q)):
                self.log.debug(f'Cleaning up queue "{name}"')
                try:
                    while True:
                        _ = q.get_nowait()
                except Empty:
                    q.close()
                    q.join_thread()

    def run_real(self):
        self.shared_memory = SharedMemory(create=True, size=self.max_shared_memory)
        self.log.debug(f'Created shared memory of size: {self.shared_memory.size / 1024 / 1024:.02f} MiB')

        # create the shared memory segments and add them to their respective pools
        for i in range(int(self.shared_memory.size / self.analysis.biggest_chunk)):
            _sms = SharedMemorySegment(offset=i * self.analysis.biggest_chunk,
                                       end=i * self.analysis.biggest_chunk + self.analysis.biggest_chunk)
            self.sms.append(_sms)

        self.log.debug(f'Created {len(self.sms)} shared memory segments.')

        # Create queues
        self.dl_worker_queue = MPQueue(-1)
        self.writer_queue = MPQueue(-1)
        self.dl_result_q = MPQueue(-1)
        self.writer_result_q = MPQueue(-1)

        self.log.info(f'Starting download workers...')

        bind_ip = None
        for i in range(self.max_workers):
            if self.bind_ips:
                bind_ip = self.bind_ips[i % len(self.bind_ips)]

            w = DLWorker(f'DLWorker {i + 1}', self.dl_worker_queue, self.dl_result_q,
                         self.shared_memory.name, logging_queue=self.logging_queue,
                         dl_timeout=self.dl_timeout, bind_addr=bind_ip)
            self.children.append(w)
            w.start()

        self.log.info('Starting file writing worker...')
        writer_p = FileWorker(self.writer_queue, self.writer_result_q, self.dl_dir,
                              self.shared_memory.name, self.cache_dir, self.logging_queue)
        self.children.append(writer_p)
        writer_p.start()

        num_chunk_tasks = sum(isinstance(t, ChunkTask) for t in self.tasks)
        num_dl_tasks = len(self.chunks_to_dl)
        num_tasks = len(self.tasks)
        num_shared_memory_segments = len(self.sms)
        self.log.debug(f'Chunks to download: {num_dl_tasks}, File tasks: {num_tasks}, Chunk tasks: {num_chunk_tasks}')

        # active downloader tasks
        self.active_tasks = 0
        processed_chunks = 0
        processed_tasks = 0
        total_dl = 0
        total_write = 0

        # synchronization conditions
        shm_cond = Condition()
        task_cond = Condition()
        self.conditions = [shm_cond, task_cond]

        # start threads
        s_time = time.time()
        self.threads.append(Thread(target=self.download_job_manager, args=(task_cond, shm_cond)))
        self.threads.append(Thread(target=self.dl_results_handler, args=(task_cond,)))
        self.threads.append(Thread(target=self.fw_results_handler, args=(shm_cond,)))

        for t in self.threads:
            t.start()

        last_update = time.time()

        while processed_tasks < num_tasks:
            delta = time.time() - last_update
            if not delta:
                time.sleep(self.update_interval)
                continue

            # update all the things
            processed_chunks += self.num_processed_since_last
            processed_tasks += self.num_tasks_processed_since_last

            total_dl += self.bytes_downloaded_since_last
            total_write += self.bytes_written_since_last

            dl_speed = self.bytes_downloaded_since_last / delta
            dl_unc_speed = self.bytes_decompressed_since_last / delta
            w_speed = self.bytes_written_since_last / delta
            r_speed = self.bytes_read_since_last / delta
            # c_speed = self.num_processed_since_last / delta

            # set temporary counters to 0
            self.bytes_read_since_last = self.bytes_written_since_last = 0
            self.bytes_downloaded_since_last = self.num_processed_since_last = 0
            self.bytes_decompressed_since_last = self.num_tasks_processed_since_last = 0
            last_update = time.time()

            perc = (processed_chunks / num_chunk_tasks) * 100
            runtime = time.time() - s_time
            total_avail = len(self.sms)
            total_used = (num_shared_memory_segments - total_avail) * (self.analysis.biggest_chunk / 1024 / 1024)

            if runtime and processed_chunks:
                average_speed = processed_chunks / runtime
                estimate = (num_chunk_tasks - processed_chunks) / average_speed
                hours, estimate = int(estimate // 3600), estimate % 3600
                minutes, seconds = int(estimate // 60), int(estimate % 60)

                rt_hours, runtime = int(runtime // 3600), runtime % 3600
                rt_minutes, rt_seconds = int(runtime // 60), int(runtime % 60)
            else:
                hours = minutes = seconds = 0
                rt_hours = rt_minutes = rt_seconds = 0

            self.log.info(f'= Progress: {perc:.02f}% ({processed_chunks}/{num_chunk_tasks}), '
                          f'Running for {rt_hours:02d}:{rt_minutes:02d}:{rt_seconds:02d}, '
                          f'ETA: {hours:02d}:{minutes:02d}:{seconds:02d}')
            self.log.info(f' - Downloaded: {total_dl / 1024 / 1024:.02f} MiB, '
                          f'Written: {total_write / 1024 / 1024:.02f} MiB')
            self.log.info(f' - Cache usage: {total_used:.02f} MiB, active tasks: {self.active_tasks}')
            self.log.info(f' + Download\t- {dl_speed / 1024 / 1024:.02f} MiB/s (raw) '
                          f'/ {dl_unc_speed / 1024 / 1024:.02f} MiB/s (decompressed)')
            self.log.info(f' + Disk\t- {w_speed / 1024 / 1024:.02f} MiB/s (write) / '
                          f'{r_speed / 1024 / 1024:.02f} MiB/s (read)')

            # send status update to back to instantiator (if queue exists)
            if self.status_queue:
                try:
                    self.status_queue.put(UIUpdate(
                        progress=perc, download_speed=dl_unc_speed, write_speed=w_speed, read_speed=r_speed,
                        memory_usage=total_used * 1024 * 1024
                    ), timeout=1.0)
                except Exception as e:
                    self.log.warning(f'Failed to send status update to queue: {e!r}')

            time.sleep(self.update_interval)

        for i in range(self.max_workers):
            self.dl_worker_queue.put_nowait(TerminateWorkerTask())

        self.log.info('Waiting for installation to finish...')
        self.writer_queue.put_nowait(TerminateWorkerTask())

        writer_p.join(timeout=10.0)
        if writer_p.exitcode is None:
            self.log.warning(f'Terminating writer process, no exit code!')
            writer_p.terminate()

        # forcibly kill DL workers that are not actually dead yet
        for child in self.children:
            if child.exitcode is None:
                child.terminate()

        # make sure all the threads are dead.
        for t in self.threads:
            t.join(timeout=5.0)
            if t.is_alive():
                self.log.warning(f'Thread did not terminate! {repr(t)}')

        # clean up resume file
        if self.resume_file:
            try:
                os.remove(self.resume_file)
            except OSError as e:
                self.log.warning(f'Failed to remove resume file: {e!r}')

        # close up shared memory
        self.shared_memory.close()
        self.shared_memory.unlink()
        self.shared_memory = None

        self.log.info('All done! Download manager quitting...')
        # finally, exit the process.
        exit(0)
