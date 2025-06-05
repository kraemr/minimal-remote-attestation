CREATE TABLE DeviceIds(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id varchar(64)
);

CREATE TABLE Attesters(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    ip_address varchar(64),
    whitelist_path varchar(256),
    whitelist_pcr_path varchar(256),
    time_added DATE
);

CREATE TABLE RemoteAttestationSession(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id NOT NULL,
    session_id varchar(64), 
    path_to_log_directory varchar(512),
    quote BINARY,
    public_key BINARY,
    last_quote_index INTEGER,
    FOREIGN KEY (device_id) REFERENCES DeviceIds (id)
);


