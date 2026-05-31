--LOCK TABLES users WRITE;

INSERT INTO users VALUES
                             (1,'admin@mail.com','Admin','Adminov','$2a$12$19K7hO/EXJaVhn/jKdNP1upVBJ3tBSP5gV3mS3wH6tUXCfyWLf3De','ADMIN','ACTIVE'),
                             (2,'user@mail.com','User','Userov','$2a$12$EhT3kf1bn4FdgXoXkJNGpuF9WHj6zlFVfsdt.G1GwFKY6bOa.tN32','USER','BANNED');

--UNLOCK TABLES;
