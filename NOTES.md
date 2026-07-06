# Omukk Web Server Log Analyzer

This document outlines the technical implementation steps, run instructions, and anomalies identified in the codebase, log files, and specifications.

---

## 1. Technical Implementation Steps

This section details how the key comment skeleton tasks from `main.py` were implemented.

### Step 1: Initialize Data Structures (`__init__`)
We initialize instance variables inside `LogAnalyzer.__init__(self)` to track metrics in real time during parsing:
* `self.filepath`: Stores the path of the active log file being processed.
* `self.log_entries`: A list storing raw dictionary representations of successfully parsed entries.
* `self.ip_counter`, `self.endpoint_counter`, and `self.status_counter`: Python `collections.Counter` objects to track request frequencies and response classifications efficiently.
* `self.total_response_size` and `self.total_requests`: Integers used to aggregate response bytes and request counts for average size calculations.
* `self.unique_ips`: A `set` that stores unique IP strings.
* `self.timestamps`: A list of datetime objects utilized to determine the analysis period.
* `self.parse_errors`: A list of dicts (`{"line": line_num, "content": line_content}`) detailing malformed lines.

### Step 2: Parse a Single Log Line (`parse_log_line`)
The log parsing logic matches a log line against a regex pattern mapping to the standard Apache Common Log Format:
```python
pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]*) HTTP/[\d\.]+" (\d+) (\d+|\-)$'
```
* **Extraction**: Extracts IP address, timestamp string, HTTP method, path, status code, and response size.
* **Timestamp Handling**: Converts the timestamp string (e.g. `10/Oct/2023:08:15:23 +0000`) into a timezone-aware python `datetime` object using `%d/%b/%Y:%H:%M:%S %z`.
* **Response Size mapping**: Checks if response size is `-`. If so, it maps it to `0` bytes.
* **Exception Handling**: Gracefully catches `ValueError` or `TypeError` during conversion, returning `None` if a line is malformed.

### Step 3: Process Entire Log File (`analyze_file`)
* **Input Validation**: Executes `validate_file` and `validate_log_format` to ensure the file exists, has a supported extension (`.txt` or `.log`), has text content (no binary null bytes), and consists of at least 10% valid log lines.
* **Line-by-Line Parsing**: Reads the file line-by-line within a `with open(...)` block using UTF-8 encoding (ignoring decode errors) to prevent loading large files entirely into RAM.
* **Progress Tracking**: Tracks progress via `bytes_read / file_size * 100` and emits progress to `progress_callback` to update the GUI thread seamlessly.
* **Aggregation**: Updates counters for parsed entries, and appends raw line data and line numbers to `self.parse_errors` for malformed lines.
* **Metric Calculation**: Sorting the timestamps at the end to get the earliest and latest log timestamps.

### Step 4: Generate and Display/Save Report (`generate_report` equivalents)
* **`generate_console_report(self)`**: 
  * Groups HTTP status codes into classes (2xx, 3xx, 4xx, 5xx) and computes rates.
  * Formats numbers with comma separators and prints top 5 active IPs and top 10 endpoints.
  * Formats parse errors displaying line numbers and malformed content.
* **`generate_json_report(self)`**:
  * Constructs a structured JSON report containing all aggregates and lists.
* **Display and Saving**:
  * In CLI mode, reports are printed directly to stdout and saved in the active directory as `output.txt` (console formatting) and `output.json` (JSON formatting).
  * In GUI mode, the report is displayed inside the Consolas text pane, and buttons let the user select where to export the files.

---

## 2. How to Run

### Run as a Desktop GUI
Run the script without arguments. If Tkinter is supported by the OS environment, it launches a graphical window:
```bash
python main.py
```

### Run in Headless CLI Mode
Pass a log filepath as a command-line argument. This runs the parser instantly and saves results to `output.txt` and `output.json` in the directory:
```bash
python main.py access.log
```

---

## 3. Notes on Anomalies, Ambiguities, and Improvements

This section outlines the ambiguities and bugs identified during implementation:

* **Expected Output JSON Syntax Error**:
  * The expected JSON in the prompt had a missing colon: `"3xx": {"count": 49, "rate" 3.9},`. We fixed this syntax error in the output parser.
* **Malformed Log Entries**:
  * `logs-small.txt` contains malformed test lines at Line 101 and Line 109, which are captured and logged in the `PARSE ERRORS` section.
* **GUI Non-Thread-Safe Execution**:
  * Tkinter is not thread-safe, but the template script updated the GUI progress bar directly from a background thread.
* **Progress Calculation Mismatches**:
  * Calculating progress using `len(line)` returns string character length, which is smaller than byte sizes for multi-byte unicode files, leading to progress tracking issues.
* **Query Parameters**:
  * Counting endpoints without splitting query parameters (e.g. `?id=1`) treats identical pages as distinct. We resolved this by extracting base endpoint paths.
* **Headless Verification Block**:
  * Headless server scripts crash on `tk.Tk()`. We implemented GUI/CLI dual execution to fall back to CLI mode when display environments are absent.
* **Timezone Offset Loss**:
  * String representations of start/end times inside report generators discard timezone offsets.
