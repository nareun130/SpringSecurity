-- Spring Security 제공 기본 테이블
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

-- 사용자 정의 테이블
create table customer(
                         id serial primary key,
                         email varchar(45) not null,
                         pwd varchar(45) not null,
                         role varchar(45) not null
);

insert into customer(email, pwd, role) values('nareun130@gmail.com','12345','admin');
-- BcryptoEncoder적용을 위해 칼럼 수정
alter table customer alter column pwd type varchar(100);