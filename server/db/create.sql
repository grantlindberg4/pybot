DROP TABLE IF EXISTS Bots;

CREATE TABLE Bots(
    addr        CHAR[20],   -- IPv4 address of vulnerable host
    port        INTEGER,    -- Vulnerable port
    username    CHAR[20],   -- username for login
    password    CHAR[20]    -- password for login
);
