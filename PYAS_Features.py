from PYAS_Diagnostics import log_exception
import os
import math
import zlib
import numpy
import pefile
import datetime


def _entropy_from_counts(counts, size):
    if size <= 0:
        return 0.0

    nonzero = counts[counts > 0]
    return float(numpy.log2(size) - numpy.sum(nonzero * numpy.log2(nonzero)) / size)


def _bounded_entropy(data, batch_size=1048576):
    size = len(data)

    if size == 0:
        return 0.0

    counts = numpy.zeros(256, dtype=numpy.int64)
    view = memoryview(data)

    try:
        for start in range(0, size, batch_size):
            chunk = numpy.frombuffer(view[start : min(start + batch_size, size)], dtype=numpy.uint8)
            counts += numpy.bincount(chunk, minlength=256)
    finally:
        view.release()

    return _entropy_from_counts(counts, size)


def _accumulate_string_chunk(chunk, array, state, pattern):
    separators = (array < 0x20) | (array > 0x7E)

    if not separators.any():
        state["pending_counts"] += numpy.bincount(array, minlength=256)
        state["pending_length"] += len(array)
        return

    first_separator = int(numpy.argmax(separators))
    last_separator = len(separators) - 1 - int(numpy.argmax(separators[::-1]))

    if first_separator:
        state["pending_counts"] += numpy.bincount(array[:first_separator], minlength=256)
        state["pending_length"] += first_separator

    if state["pending_length"] >= 5:
        state["count"] += 1
        state["total_length"] += state["pending_length"]
        state["counts"] += state["pending_counts"]

    state["pending_length"] = 0
    state["pending_counts"].fill(0)

    middle_start = first_separator + 1
    middle_end = last_separator

    if middle_end > middle_start:
        matches = pattern.findall(chunk[middle_start:middle_end])

        if matches:
            combined = b"".join(matches)
            state["count"] += len(matches)
            state["total_length"] += len(combined)
            state["counts"] += numpy.bincount(
                numpy.frombuffer(combined, dtype=numpy.uint8), minlength=256
            )

    trailing_start = last_separator + 1

    if trailing_start < len(array):
        trailing = array[trailing_start:]
        state["pending_counts"] += numpy.bincount(trailing, minlength=256)
        state["pending_length"] = len(trailing)


def _accumulate_entropy_windows(data, entropy_histogram, c_log_c_table):
    block_count = len(data) // 1024

    if block_count < 2:
        return data

    complete_size = block_count * 1024
    blocks = numpy.frombuffer(data, dtype=numpy.uint8, count=complete_size).reshape(
        block_count, 1024
    )
    encoded = blocks.astype(numpy.int32)
    encoded += numpy.arange(block_count, dtype=numpy.int32)[:, None] * 256
    block_counts = numpy.bincount(encoded.ravel(), minlength=block_count * 256).reshape(
        block_count, 256
    )
    window_counts = block_counts[:-1] + block_counts[1:]
    sum_c_log_c = numpy.sum(c_log_c_table[window_counts], axis=1)
    entropies = 11.0 - sum_c_log_c / 2048.0
    entropy_bins = (entropies * 2.0).astype(numpy.int32)
    numpy.clip(entropy_bins, 0, 15, out=entropy_bins)
    byte_bins = window_counts.reshape(block_count - 1, 16, 16).sum(axis=2)
    flat_indices = (entropy_bins[:, None] * 16 + numpy.arange(16)).ravel()
    numpy.add.at(entropy_histogram, flat_indices, byte_bins.ravel())
    return data[(block_count - 1) * 1024 :]


def _collect_resource_ranges(pe, file_size):
    ranges = []

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return ranges

    for entry_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry_id in getattr(getattr(entry_type, "directory", None), "entries", []):
            for entry_lang in getattr(getattr(entry_id, "directory", None), "entries", []):
                if not hasattr(entry_lang, "data"):
                    continue

                try:
                    struct = entry_lang.data.struct
                    offset = int(pe.get_offset_from_rva(int(struct.OffsetToData)))
                    size = int(struct.Size)
                    start = max(0, offset)
                    end = min(file_size, start + max(0, size))
                    ranges.append((start, max(start, end)))
                except Exception:
                    log_exception("PYAS_Features._collect_resource_ranges:109")
                    ranges.append((0, 0))

    return ranges


def _extract_stream_features(file_path, file_size, ranges, extractor):
    normalized = []

    for start, end in ranges:
        start = max(0, min(file_size, int(start)))
        end = max(start, min(file_size, int(end)))
        normalized.append((start, end))

    byte_counts = numpy.zeros(256, dtype=numpy.int64)
    range_counts = [numpy.zeros(256, dtype=numpy.int64) for _ in normalized]
    entropy_histogram = numpy.zeros(256, dtype=numpy.float64)
    string_state = {
        "count": 0,
        "total_length": 0,
        "counts": numpy.zeros(256, dtype=numpy.int64),
        "pending_length": 0,
        "pending_counts": numpy.zeros(256, dtype=numpy.int64),
    }
    histogram_tail = b""
    position = 0

    with open(file_path, "rb") as source:
        while True:
            chunk = source.read(4194304)

            if not chunk:
                break

            array = numpy.frombuffer(chunk, dtype=numpy.uint8)
            _accumulate_string_chunk(chunk, array, string_state, extractor._STRING_PATTERN)
            histogram_tail = _accumulate_entropy_windows(
                histogram_tail + chunk,
                entropy_histogram,
                extractor._C_LOG_C_TABLE,
            )

            chunk_end = position + len(chunk)
            boundaries = {0, len(chunk)}

            for start, end in normalized:
                if position < start < chunk_end:
                    boundaries.add(start - position)

                if position < end < chunk_end:
                    boundaries.add(end - position)

            ordered = sorted(boundaries)

            for index in range(len(ordered) - 1):
                local_start = ordered[index]
                local_end = ordered[index + 1]

                if local_end <= local_start:
                    continue

                counts = numpy.bincount(array[local_start:local_end], minlength=256)
                byte_counts += counts
                absolute_start = position + local_start
                absolute_end = position + local_end

                for range_index, (start, end) in enumerate(normalized):
                    if start <= absolute_start and absolute_end <= end:
                        range_counts[range_index] += counts

            position = chunk_end

    if string_state["pending_length"] >= 5:
        string_state["count"] += 1
        string_state["total_length"] += string_state["pending_length"]
        string_state["counts"] += string_state["pending_counts"]

    string_count = string_state["count"]
    total_string_length = string_state["total_length"]
    result = {
        "StringCount": float(string_count),
        "StringMeanLength": (float(total_string_length) / string_count if string_count else 0.0),
        "StringEntropy": _entropy_from_counts(string_state["counts"], total_string_length),
    }
    result.update(dict.fromkeys(extractor._STRING_KEYS, 0.0))

    if total_string_length:
        valid_counts = string_state["counts"][0x20:0x7F]
        result.update(
            dict(
                zip(
                    extractor._STRING_KEYS,
                    valid_counts.astype(numpy.float64) / total_string_length,
                )
            )
        )

    result["FileEntropy"] = _entropy_from_counts(byte_counts, file_size)
    result.update(
        dict(
            zip(
                extractor._BYTE_HIST_KEYS,
                byte_counts.astype(numpy.float64) / file_size,
            )
        )
    )
    entropy_sum = numpy.sum(entropy_histogram)

    if entropy_sum:
        entropy_histogram /= entropy_sum

    result.update(dict(zip(extractor._BYTE_ENT_KEYS, entropy_histogram)))

    range_entropies = [
        _entropy_from_counts(counts, end - start)
        for counts, (start, end) in zip(range_counts, normalized)
    ]
    return result, range_entropies


class PEFeatureMixin:
    def _safe_float(self, val):
        try:
            f = float(val)

            if math.isinf(f) or math.isnan(f):
                return 0.0

            return f
        except Exception:
            log_exception("PYAS_Features.PEFeatureMixin._safe_float:221")
            return 0.0

    def _base_defaults(self):
        base = dict.fromkeys(self._OPTIONAL_HEADER_FIELDS, 0.0)
        base.update(self._SECTION_DEFAULTS)
        base.update(self._CONDITIONAL_DEFAULTS)

        for i in range(16):
            base[f"DataDirectory_{i}_Size"] = 0.0
            base[f"DataDirectory_{i}_VA"] = 0.0

        return base

    def _calc_entropy(self, data):
        return _bounded_entropy(data)

    def _extract_strings(self, file_bytes):
        res = {"StringCount": 0.0, "StringMeanLength": 0.0, "StringEntropy": 0.0}
        res.update(dict.fromkeys(self._STRING_KEYS, 0.0))

        if len(file_bytes) <= self._STRING_FAST_PATH_BYTES:
            matches = self._STRING_PATTERN.findall(file_bytes)

            if not matches:
                return res

            combined_data = b"".join(matches)
            count = len(matches)
            total_len = len(combined_data)
            global_counts = numpy.bincount(
                numpy.frombuffer(combined_data, dtype=numpy.uint8), minlength=256
            )
        else:
            count = 0
            total_len = 0
            global_counts = numpy.zeros(256, dtype=numpy.int64)
            mv = memoryview(file_bytes)
            pos = 0
            size = len(file_bytes)

            while pos < size:
                chunk_end = min(pos + self._STRING_BATCH_BYTES, size)
                chunk_arr = numpy.frombuffer(mv[pos:chunk_end], dtype=numpy.uint8)
                separators = (chunk_arr < 0x20) | (chunk_arr > 0x7E)

                if separators.any():
                    last_separator = len(separators) - 1 - int(numpy.argmax(separators[::-1]))
                    segment_end = pos + last_separator + 1
                    matches = self._STRING_PATTERN.findall(mv[pos:segment_end])

                    if matches:
                        combined_data = b"".join(matches)
                        count += len(matches)
                        total_len += len(combined_data)
                        global_counts += numpy.bincount(
                            numpy.frombuffer(combined_data, dtype=numpy.uint8), minlength=256
                        )

                    pos = segment_end
                    continue

                pending_len = 0
                pending_counts = numpy.zeros(256, dtype=numpy.int64)

                while pos < size:
                    chunk_end = min(pos + self._STRING_BATCH_BYTES, size)
                    chunk_arr = numpy.frombuffer(mv[pos:chunk_end], dtype=numpy.uint8)
                    separators = (chunk_arr < 0x20) | (chunk_arr > 0x7E)

                    if separators.any():
                        first_separator = int(numpy.argmax(separators))

                        if first_separator:
                            pending_counts += numpy.bincount(
                                chunk_arr[:first_separator], minlength=256
                            )
                            pending_len += first_separator

                        pos += first_separator + 1
                        break

                    pending_counts += numpy.bincount(chunk_arr, minlength=256)
                    pending_len += len(chunk_arr)
                    pos = chunk_end

                if pending_len >= 5:
                    count += 1
                    total_len += pending_len
                    global_counts += pending_counts

            if count == 0 or total_len == 0:
                return res

        res["StringCount"] = float(count)
        res["StringMeanLength"] = float(total_len) / count

        counts_nonzero = global_counts[global_counts > 0]

        if len(counts_nonzero) > 0:
            res["StringEntropy"] = float(
                numpy.log2(total_len)
                - numpy.sum(counts_nonzero * numpy.log2(counts_nonzero)) / total_len
            )

        valid_chars = global_counts[0x20:0x7F]
        res.update(dict(zip(self._STRING_KEYS, valid_chars.astype(numpy.float64) / total_len)))

        return res

    def _extract_histograms(self, file_bytes):
        arr = numpy.frombuffer(file_bytes, dtype=numpy.uint8)
        sz = len(arr)
        res = {}

        if sz == 0:
            res["FileEntropy"] = 0.0
            res.update(dict.fromkeys(self._BYTE_HIST_KEYS, 0.0))
            res.update(dict.fromkeys(self._BYTE_ENT_KEYS, 0.0))
            return res

        byte_counts = numpy.zeros(256, dtype=numpy.int64)
        ent_hist = numpy.zeros(256, dtype=numpy.float64)
        window = 2048
        step = 1024

        if sz < window:
            byte_counts += numpy.bincount(arr, minlength=256)
            p = byte_counts[byte_counts > 0] / float(sz)
            entropy = float(-numpy.sum(p * numpy.log2(p)))
            ent_bin = min(int(entropy * 2.0), 15)
            byte_bins = byte_counts.reshape(16, 16).sum(axis=1)
            idx_start = ent_bin * 16
            ent_hist[idx_start : idx_start + 16] += byte_bins
        else:
            num_windows = (sz - window) // step + 1

            for w_start in range(0, num_windows, self._HISTOGRAM_BATCH_WINDOWS):
                w_end = min(w_start + self._HISTOGRAM_BATCH_WINDOWS, num_windows)
                b_num = w_end - w_start

                start_byte = w_start * step
                end_byte = start_byte + b_num * step + step
                encoded = arr[start_byte:end_byte].astype(numpy.int32).reshape(b_num + 1, step)
                encoded += numpy.arange(b_num + 1, dtype=numpy.int32)[:, None] * 256

                chunk_counts = numpy.bincount(encoded.ravel(), minlength=(b_num + 1) * 256).reshape(
                    b_num + 1, 256
                )
                del encoded

                byte_counts += numpy.sum(chunk_counts[:-1], axis=0)

                if w_end == num_windows:
                    byte_counts += chunk_counts[-1]

                window_counts = chunk_counts[:-1] + chunk_counts[1:]
                sum_c_log_c = numpy.sum(self._C_LOG_C_TABLE[window_counts], axis=1)
                entropies = 11.0 - sum_c_log_c / 2048.0

                ent_bins = (entropies * 2.0).astype(numpy.int32)
                numpy.clip(ent_bins, 0, 15, out=ent_bins)

                byte_bins = window_counts.reshape(b_num, 16, 16).sum(axis=2)
                flat_ent_bins = (ent_bins[:, None] * 16 + numpy.arange(16)).ravel()
                numpy.add.at(ent_hist, flat_ent_bins, byte_bins.ravel())

            covered_size = (num_windows + 1) * step

            if covered_size < sz:
                byte_counts += numpy.bincount(arr[covered_size:], minlength=256)

        counts_nonzero = byte_counts[byte_counts > 0]
        res["FileEntropy"] = float(
            numpy.log2(sz) - numpy.sum(counts_nonzero * numpy.log2(counts_nonzero)) / sz
        )

        byte_hist = byte_counts.astype(numpy.float64) / sz
        res.update(dict(zip(self._BYTE_HIST_KEYS, byte_hist)))

        ent_sum = numpy.sum(ent_hist)

        if ent_sum > 0:
            ent_hist /= ent_sum

        res.update(dict(zip(self._BYTE_ENT_KEYS, ent_hist)))
        return res

    def _extract_overlay_features(self, pe, fsize):
        overlay_offset = pe.get_overlay_data_start_offset()

        if not overlay_offset or overlay_offset >= fsize:
            return {
                "HasOverlay": 0.0,
                "OverlaySize": 0.0,
                "OverlayRatio": 0.0,
                "OverlayEntropy": 0.0,
            }

        overlay_data = pe.get_overlay()

        if not overlay_data:
            return {
                "HasOverlay": 0.0,
                "OverlaySize": 0.0,
                "OverlayRatio": 0.0,
                "OverlayEntropy": 0.0,
            }

        sz = len(overlay_data)
        return {
            "HasOverlay": 1.0,
            "OverlaySize": float(sz),
            "OverlayRatio": float(sz) / float(fsize),
            "OverlayEntropy": self._calc_entropy(overlay_data),
        }

    def _extract_rich_header(self, pe):
        if not hasattr(pe, "RICH_HEADER") or not pe.RICH_HEADER:
            return {"HasRichHeader": 0.0, "RichHeaderCount": 0.0}

        return {
            "HasRichHeader": 1.0,
            "RichHeaderCount": (
                float(len(pe.RICH_HEADER.values) // 2) if hasattr(pe.RICH_HEADER, "values") else 0.0
            ),
        }

    def _extract_ep_anomalies(self, pe):
        if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe, "sections") or not pe.sections:
            return {
                "EntryPointSectionIndex": -1.0,
                "EntryPointInExecutable": 0.0,
                "EntryPointInLastSection": 0.0,
            }

        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section_idx = -1
        ep_in_exec = 0.0

        for idx, sec in enumerate(pe.sections):
            if sec.VirtualAddress <= ep < (sec.VirtualAddress + sec.Misc_VirtualSize):
                ep_section_idx = idx

                if sec.Characteristics & 0x20000000:
                    ep_in_exec = 1.0

                break

        return {
            "EntryPointSectionIndex": float(ep_section_idx),
            "EntryPointInExecutable": ep_in_exec,
            "EntryPointInLastSection": 1.0 if ep_section_idx == len(pe.sections) - 1 else 0.0,
        }

    def _extract_advanced_resources(self, pe, range_entropies=None):
        res_data = {
            "ResourceMaxEntropy": 0.0,
            "ResourceMinEntropy": 0.0,
            "ResourceMeanEntropy": 0.0,
            "ResourceLangCount": 0.0,
            "ResourceRCDataCount": 0.0,
        }

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return res_data

        entropies = []
        entropy_iter = iter(range_entropies or ())
        langs = set()
        rcdata_count = 0

        for entry_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry_type, "id") and entry_type.id == 10:
                rcdata_count += len(getattr(entry_type.directory, "entries", []))

            if not hasattr(entry_type, "directory"):
                continue

            for entry_id in entry_type.directory.entries:
                if not hasattr(entry_id, "directory"):
                    continue

                for entry_lang in entry_id.directory.entries:
                    if hasattr(entry_lang, "id"):
                        langs.add(entry_lang.id)

                    if hasattr(entry_lang, "data"):
                        try:
                            entropies.append(float(next(entropy_iter)))
                        except (StopIteration, TypeError, ValueError):
                            entropies.append(0.0)

        res_data["ResourceLangCount"] = float(len(langs))
        res_data["ResourceRCDataCount"] = float(rcdata_count)

        if entropies:
            res_data["ResourceMaxEntropy"] = max(entropies)
            res_data["ResourceMinEntropy"] = min(entropies)
            res_data["ResourceMeanEntropy"] = sum(entropies) / len(entropies)

        return res_data

    def _extract_load_config(self, pe):
        cfg = {"HasLoadConfig": 0.0, "HasCFG": 0.0, "HasSEHTable": 0.0}

        if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
            cfg["HasLoadConfig"] = 1.0
            struct = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct

            if getattr(struct, "GuardCFFunctionTable", 0) != 0:
                cfg["HasCFG"] = 1.0

            if getattr(struct, "SEHandlerTable", 0) != 0:
                cfg["HasSEHTable"] = 1.0

        return cfg

    def _extract_security_directory(self, pe, file_path, fsize):
        res = {"HasSignature": 0.0, "SignatureCount": 0.0}

        if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            return res

        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY

        if len(directories) <= 4:
            return res

        sec_dir = directories[4]
        offset = int(sec_dir.VirtualAddress)
        size = int(sec_dir.Size)

        if offset <= 0 or size <= 0 or offset + size > fsize:
            return res

        res["HasSignature"] = 1.0
        count = 0
        curr = offset
        end = offset + size

        with open(file_path, "rb") as source:
            while curr + 8 <= end:
                source.seek(curr)
                header = source.read(4)

                if len(header) != 4:
                    break

                length = int.from_bytes(header, "little")

                if length < 8 or curr + length > end:
                    break

                count += 1
                curr += (length + 7) & ~7

        res["SignatureCount"] = float(count)
        return res

    def extract_features(self, file_path):
        pe = None

        try:
            fsize = os.path.getsize(file_path)

            if fsize == 0 or fsize > 4294967296:
                return None

            base = self._base_defaults()
            dlls = set()
            apis = set()
            pe = pefile.PE(name=file_path, fast_load=True)

            try:
                pe.parse_rich_header()
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
                    ]
                )
            except Exception:
                log_exception("PYAS_Features.PEFeatureMixin.extract_features:553")
                pass

            sections = list(getattr(pe, "sections", []))
            section_ranges = []

            for section in sections:
                start = max(0, int(section.get_PointerToRawData_adj()))
                end = min(fsize, start + max(0, int(section.SizeOfRawData)))
                section_ranges.append((start, max(start, end)))

            resource_ranges = _collect_resource_ranges(pe, fsize)
            overlay_offset = pe.get_overlay_data_start_offset()

            if not overlay_offset or overlay_offset >= fsize:
                overlay_offset = fsize

            all_ranges = section_ranges + resource_ranges + [(int(overlay_offset), fsize)]
            stream_features, range_entropies = _extract_stream_features(
                file_path, fsize, all_ranges, self
            )
            section_entropies = range_entropies[: len(section_ranges)]
            resource_start = len(section_ranges)
            resource_entropies = range_entropies[
                resource_start : resource_start + len(resource_ranges)
            ]
            overlay_entropy = range_entropies[-1]

            base["TrustSigned"] = 1.0 if self.signer.sign_verify(file_path) else 0.0
            base["FileSize"] = float(fsize)

            fh = pe.FILE_HEADER
            base["Machine"] = getattr(fh, "Machine", 0)
            base["NumberOfSections"] = getattr(fh, "NumberOfSections", 0)
            base["TimeDateStamp"] = getattr(fh, "TimeDateStamp", 0)
            base["PointerToSymbolTable"] = getattr(fh, "PointerToSymbolTable", 0)
            base["NumberOfSymbols"] = getattr(fh, "NumberOfSymbols", 0)
            base["SizeOfOptionalHeader"] = getattr(fh, "SizeOfOptionalHeader", 0)
            base["Characteristics"] = getattr(fh, "Characteristics", 0)

            curr_ts = datetime.datetime.utcnow().timestamp()
            base["HasInvalidTimestamp"] = (
                1.0
                if (base["TimeDateStamp"] < 631152000 or base["TimeDateStamp"] > curr_ts + 2592000)
                else 0.0
            )
            base["FileTimeException"] = 1.0 if base["TimeDateStamp"] == 0 else 0.0
            base["Is64Bit"] = 1.0 if base["Machine"] in (0x8664, 0xAA64, 0x0200) else 0.0
            base["IsExe"] = 1.0 if pe.is_exe() else 0.0
            base["IsDll"] = 1.0 if pe.is_dll() else 0.0
            base["ExceptionCount"] = 0.0

            if hasattr(pe, "OPTIONAL_HEADER"):
                op = pe.OPTIONAL_HEADER
                fields = [
                    "Magic",
                    "MajorLinkerVersion",
                    "MinorLinkerVersion",
                    "SizeOfCode",
                    "SizeOfInitializedData",
                    "SizeOfUninitializedData",
                    "AddressOfEntryPoint",
                    "BaseOfCode",
                    "ImageBase",
                    "SectionAlignment",
                    "FileAlignment",
                    "MajorOperatingSystemVersion",
                    "MinorOperatingSystemVersion",
                    "MajorImageVersion",
                    "MinorImageVersion",
                    "MajorSubsystemVersion",
                    "MinorSubsystemVersion",
                    "SizeOfImage",
                    "SizeOfHeaders",
                    "CheckSum",
                    "Subsystem",
                    "DllCharacteristics",
                    "SizeOfStackReserve",
                    "SizeOfStackCommit",
                    "SizeOfHeapReserve",
                    "SizeOfHeapCommit",
                    "LoaderFlags",
                    "NumberOfRvaAndSizes",
                ]

                for f_field in fields:
                    base[f_field] = getattr(op, f_field, 0)

                base["IsDriver"] = 1.0 if base.get("Subsystem") == 1 else 0.0

                if hasattr(op, "DATA_DIRECTORY"):
                    for i, directory in enumerate(op.DATA_DIRECTORY):
                        base[f"DataDirectory_{i}_Size"] = directory.Size
                        base[f"DataDirectory_{i}_VA"] = directory.VirtualAddress

                    exc_idx = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 3)

                    if len(op.DATA_DIRECTORY) > exc_idx and op.DATA_DIRECTORY[exc_idx].Size > 0:
                        base["ExceptionCount"] = (
                            op.DATA_DIRECTORY[exc_idx].Size // 12
                            if base["Machine"] in (0x8664, 0xAA64)
                            else 0.0
                        )

            res_flags_count = dict.fromkeys(self._CHAR_COUNT_KEYS.values(), 0.0)
            res_flags_ent = dict.fromkeys(self._CHAR_ENT_KEYS.values(), 0.0)
            res_sec_hash = dict.fromkeys(self._SECTION_HASH_KEYS, 0.0)

            if hasattr(pe, "sections"):
                base["SectionCount"] = len(pe.sections)
                entropies = []
                raw_sizes = []
                v_sizes = []
                exec_sec = write_sec = read_sec = sec_exc = 0

                for section_index, section in enumerate(pe.sections):
                    sec_name = section.Name.rstrip(b"\x00")
                    hash_val = zlib.crc32(sec_name) % 50
                    res_sec_hash[self._SECTION_HASH_KEYS[hash_val]] += 1.0

                    s_entropy = (
                        section_entropies[section_index]
                        if section_index < len(section_entropies)
                        else 0.0
                    )

                    entropies.append(s_entropy)
                    raw_sizes.append(section.SizeOfRawData)
                    v_sizes.append(section.Misc_VirtualSize)

                    if section.Characteristics & 0x20000000:
                        exec_sec += 1

                    if section.Characteristics & 0x80000000:
                        write_sec += 1

                    if section.Characteristics & 0x40000000:
                        read_sec += 1

                    if section.SizeOfRawData + section.PointerToRawData > fsize:
                        sec_exc = 1

                    for flag in self._CHAR_FLAGS:
                        if section.Characteristics & flag:
                            res_flags_count[self._CHAR_COUNT_KEYS[flag]] += 1.0
                            res_flags_ent[self._CHAR_ENT_KEYS[flag]] += s_entropy

                base["SectionMaxEntropy"] = max(entropies) if entropies else 0.0
                base["SectionMinEntropy"] = min(entropies) if entropies else 0.0
                base["SectionMeanEntropy"] = sum(entropies) / len(entropies) if entropies else 0.0
                base["SectionMaxRawSize"] = max(raw_sizes) if raw_sizes else 0.0
                base["SectionMinRawSize"] = min(raw_sizes) if raw_sizes else 0.0
                base["SectionMeanRawSize"] = sum(raw_sizes) / len(raw_sizes) if raw_sizes else 0.0
                base["SectionMaxVSize"] = max(v_sizes) if v_sizes else 0.0
                base["SectionMinVSize"] = min(v_sizes) if v_sizes else 0.0
                base["SectionMeanVSize"] = sum(v_sizes) / len(v_sizes) if v_sizes else 0.0
                base["ExecutableSections"] = float(exec_sec)
                base["WritableSections"] = float(write_sec)
                base["ReadableSections"] = float(read_sec)
                base["SectionException"] = float(sec_exc)

                for flag in self._CHAR_FLAGS:
                    cnt_key = self._CHAR_COUNT_KEYS[flag]

                    if res_flags_count[cnt_key] > 0:
                        res_flags_ent[self._CHAR_ENT_KEYS[flag]] /= res_flags_count[cnt_key]

            base.update(res_flags_count)
            base.update(res_flags_ent)
            base.update(res_sec_hash)

            string_keys = [
                "FileDescription",
                "FileVersion",
                "ProductName",
                "ProductVersion",
                "CompanyName",
                "LegalCopyright",
                "Comments",
                "InternalName",
                "LegalTrademarks",
                "SpecialBuild",
                "PrivateBuild",
            ]

            for key in string_keys:
                base[f"{key}Length"] = 0.0

            if hasattr(pe, "FileInfo"):
                for fileinfo_list in pe.FileInfo:
                    for fileinfo in fileinfo_list:

                        if getattr(fileinfo, "name", "") in ("StringFileInfo", b"StringFileInfo"):
                            for st in getattr(fileinfo, "StringTable", []):
                                for key, val in st.entries.items():
                                    try:
                                        k = (
                                            key.decode("utf-8", "ignore")
                                            if isinstance(key, bytes)
                                            else str(key)
                                        )

                                        if k in string_keys:
                                            v = (
                                                val.decode("utf-8", "ignore")
                                                if isinstance(val, bytes)
                                                else str(val)
                                            )
                                            base[f"{k}Length"] = float(len(v))

                                    except Exception:
                                        log_exception(
                                            "PYAS_Features.PEFeatureMixin.extract_features:704"
                                        )
                                        continue

            if hasattr(pe, "DIRECTORY_ENTRY_TLS") and hasattr(pe.DIRECTORY_ENTRY_TLS, "struct"):
                if getattr(pe.DIRECTORY_ENTRY_TLS.struct, "AddressOfCallBacks", 0) != 0:
                    base["HasTlsCallbacks"] = 1.0

            if hasattr(pe, "VS_FIXEDFILEINFO") and len(pe.VS_FIXEDFILEINFO) > 0:
                flags = getattr(pe.VS_FIXEDFILEINFO[0], "FileFlags", 0)
                base["IsDebug"] = 1.0 if flags & 0x1 else 0.0
                base["IsPreRelease"] = 1.0 if flags & 0x2 else 0.0
                base["IsPatched"] = 1.0 if flags & 0x4 else 0.0
                base["IsPrivateBuild"] = 1.0 if flags & 0x8 else 0.0
                base["IsSpecialBuild"] = 1.0 if flags & 0x20 else 0.0

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                base["ImportCount"] = float(len(pe.DIRECTORY_ENTRY_IMPORT))
                func_count = 0

                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if getattr(entry, "dll", None):
                        try:
                            dlls.add(entry.dll.decode("ascii", "ignore").lower())
                        except Exception:
                            log_exception("PYAS_Features.PEFeatureMixin.extract_features:727")
                            pass

                    for imp in getattr(entry, "imports", []):
                        func_count += 1

                        if getattr(imp, "name", None):
                            try:
                                apis.add(imp.name.decode("ascii", "ignore"))
                            except Exception:
                                log_exception("PYAS_Features.PEFeatureMixin.extract_features:735")
                                pass

                base["ImportFunctionCount"] = float(func_count)
            else:
                base["ImportCount"] = 0.0
                base["ImportFunctionCount"] = 0.0

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and hasattr(
                pe.DIRECTORY_ENTRY_EXPORT, "symbols"
            ):
                base["ExportCount"] = float(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
            else:
                base["ExportCount"] = 0.0

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                icon_count = 0

                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if getattr(entry, "id", None) == 3 and hasattr(entry, "directory"):
                        icon_count += len(getattr(entry.directory, "entries", []))

                base["IconCount"] = float(icon_count)
            else:
                base["IconCount"] = 0.0

            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                base["DebugCount"] = float(len(pe.DIRECTORY_ENTRY_DEBUG))
            else:
                base["DebugCount"] = 0.0

            base.update(stream_features)
            overlay_size = fsize - int(overlay_offset)
            base.update(
                {
                    "HasOverlay": 1.0 if overlay_size else 0.0,
                    "OverlaySize": float(overlay_size),
                    "OverlayRatio": float(overlay_size) / float(fsize) if overlay_size else 0.0,
                    "OverlayEntropy": overlay_entropy if overlay_size else 0.0,
                }
            )
            base.update(self._extract_rich_header(pe))
            base.update(self._extract_ep_anomalies(pe))
            base.update(self._extract_advanced_resources(pe, resource_entropies))
            base.update(self._extract_load_config(pe))
            base.update(self._extract_security_directory(pe, file_path, fsize))

            for k in base:
                base[k] = self._safe_float(base[k])

            return {"Base": base, "DLLs": list(dlls), "APIs": list(apis)}

        except Exception:
            log_exception("PYAS_Features.PEFeatureMixin.extract_features:782")
            return None
        finally:
            if pe:
                pe.close()
