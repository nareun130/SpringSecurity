create table users
(
    id       serial primary key,
    username varchar(45) not null,
    password varchar(45) not null,
    enabled  int         not null
);


create table authorities
(
    id        serial primary key,
    username  varchar(45) not null,
    authority varchar(45) not null
);

insert into users(username, password, enabled)
values ('nareun', '12345', 1);
insert into authorities(username, authority)
values ('nareun', 'write');
