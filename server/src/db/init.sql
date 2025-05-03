
CREATE TABLE DeviceIds(id SERIAL PRIMARY KEY, device_id char(64));
CREATE TABLE RemoteAttestationSession(
    id SERIAL PRIMARY KEY, device_id,
    session_id char(64), 
    path_to_log varchar(512),
    quote BINARY,
    public_key BINARY,
    last_quote_index INTEGER
);