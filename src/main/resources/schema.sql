CREATE TABLE users (
  username VARCHAR(50) NOT NULL,
  password VARCHAR(250) NOT NULL,
  PRIMARY KEY (username)
);
  
CREATE TABLE groups (
  username VARCHAR(50) NOT NULL REFERENCES users(username) on delete cascade on update cascade,
  usergroup VARCHAR(50) NOT NULL,
  PRIMARY key (username, usergroup)
);