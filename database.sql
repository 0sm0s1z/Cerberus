CREATE TABLE Hosts(
   ID INTEGER PRIMARY KEY   AUTOINCREMENT,
   Host           VARCHAR(100)   NOT NULL,
   Context        VARCHAR(100),
   Description     VARCHAR(100),
   Status         VARCHAR(100)
);


insert into hosts (Host, Context, Description, Status)
VALUES ("10.0.0.200", "NT AUTHORITY/SYSTEM", "Implant: Ravenclaw, OS: Windows", "52s");


CREATE TABLE Implants(
   ID INT PRIMARY KEY            NOT NULL,
   Host           VARCHAR(100)   NOT NULL,
   Context        VARCHAR(100),
   Descripton     VARCHAR(100),
   Status         VARCHAR(100)
);

CREATE TABLE C2_Profiles(
   ID INT PRIMARY KEY            NOT NULL,
   Host           VARCHAR(100)   NOT NULL,
   Context        VARCHAR(100),
   Descripton     VARCHAR(100),
   Status         VARCHAR(100)
);

