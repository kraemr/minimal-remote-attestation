

CREATE TABLE DeviceIds(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id char(64)
);

CREATE TABLE RemoteAttestationSession(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id NOT NULL,
    session_id char(64), 
    path_to_log_directory varchar(512),
    quote BINARY,
    public_key BINARY,
    last_quote_index INTEGER,
    FOREIGN KEY (device_id) REFERENCES DeviceIds (id)
);


