def log_event(event_type, file_path, previous_metadata=None, new_metadata=None, previous_hash=None, new_hash=None):
    """Log file change events in JSON format with detailed metadata."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "file_path": file_path,
        "previous_metadata": previous_metadata,
        "new_metadata": new_metadata,
        "previous_hash": previous_hash,
        "new_hash": new_hash
    }

    # Write to local log file
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry) + "\n")

    # Send log to Splunk
    audit.send_to_splunk(log_entry)
