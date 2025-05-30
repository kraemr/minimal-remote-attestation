g++ src/*.cpp ../common/encoding.c ../common/verify_ek_cert.c ../common/ima_log_lib/src/*.c -lssl -lcrypto -lcbor -luuid -fpermissive -ltss2-esys -ltss2-mu -lsqlite3 -fsanitize=address
