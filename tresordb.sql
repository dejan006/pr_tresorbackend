--
-- Datenbank: `tresordb`
--

DROP DATABASE IF EXISTS tresordb;
CREATE DATABASE tresordb;
USE tresordb;

-- --------------------------------------------------------

--
-- table user
--

-- Hinzufügen von encription_salt für die Encryption

CREATE TABLE user (
    id int NOT NULL AUTO_INCREMENT,
    first_name varchar(30) NOT NULL,
    last_name varchar(30) NOT NULL,
    email varchar(30) NOT NULL,
    password longtext NOT NULL,
    encryption_salt varchar(24) NOT NULL,
    password_salt   VARCHAR(24) NOT NULL, 
    PRIMARY KEY (id)
);

--
-- table user content
--

-- Daten befüllen mit dem neuen encryption_salt feld
INSERT INTO `user` (`id`,`first_name`,`last_name`,`email`,`password`,`encryption_salt`) VALUES
(1, 'Hans','Muster','hans.muster@bbw.ch','abcd','AAAAAAAAAAAAAAAAAAAAAA'),
(2, 'Paula','Kuster','paula.kuster@bbw.ch','efgh','BBBBBBBBBBBBBBBBBBBBBB'),
(3, 'Andrea','Oester','andrea.oester@bbw.ch','ijkl','CCCCCCCCCCCCCCCCCCCCCC');

--
-- table secret
--

CREATE TABLE secret (
    id int NOT NULL AUTO_INCREMENT,
    user_id int NOT NULL,
    content LONGTEXT NOT NULL,
    PRIMARY KEY (id)
);

--
-- table secret content
--

INSERT INTO `secret` (`id`, `user_id`, `content`) VALUES
    (1, 1, '{"kindid":1,"kind":"credential","userName":"muster","password":"1234","url":"www.bbw.ch"}'),
    (2, 1, '{"kindid":2,"kind":"creditcard","cardtype":"Visa","cardnumber":"4242 4242 4242 4241","expiration":"12/27","cvv":"789"}'),
    (3, 1, '{"kindid":3,"kind":"note","title":"Eragon","content":"Und Eragon ging auf den Drachen zu."}');
