create table CUSTOMER
(
    customer_id   serial primary key,
    name          varchar(100) not null,
    email         varchar(100) not null,
    mobile_number varchar(100) not null,
    pwd           varchar(500) not null,
    role          varchar(100) not null,
    create_dt     date default null
);

select *
from CUSTOMER C;
insert into CUSTOMER(name, email, mobile_number, pwd, role, create_dt)
values ('Happy', 'happy@example.com', '9876548337', '$2a$10$R47TmMTWS6jn4CSItEai/ecj9mBSYDbguXbL6/0ogSBprYsxhSr/e
', 'admin', now());
select *
from CUSTOMER C;

CREATE TABLE accounts
(
    customer_id    INTEGER      NOT NULL,
    account_number BIGINT       NOT NULL,
    account_type   VARCHAR(100) NOT NULL,
    branch_address VARCHAR(200) NOT NULL,
    create_dt      DATE DEFAULT NULL,
    PRIMARY KEY (account_number),
    CONSTRAINT fk_customer
        FOREIGN KEY (customer_id)
            REFERENCES customer (customer_id)
            ON DELETE CASCADE
);


CREATE INDEX idx_accounts_customer_id ON accounts (customer_id);

insert into accounts(customer_id, account_number, account_type, branch_address, create_dt)
values (1, 186576453434, 'Savings', '123 Main Street, New York', CURRENT_DATE);

CREATE TABLE account_transactions
(
    transaction_id      VARCHAR(200) NOT NULL,
    account_number      BIGINT       NOT NULL,
    customer_id         INTEGER      NOT NULL,
    transaction_dt      DATE         NOT NULL,
    transaction_summary VARCHAR(200) NOT NULL,
    transaction_type    VARCHAR(100) NOT NULL,
    transaction_amt     INTEGER      NOT NULL,
    closing_balance     INTEGER      NOT NULL,
    create_dt           DATE DEFAULT NULL,
    PRIMARY KEY (transaction_id),
    CONSTRAINT fk_accounts FOREIGN KEY (account_number)
        REFERENCES accounts (account_number) ON DELETE CASCADE,
    CONSTRAINT fk_customer FOREIGN KEY (customer_id)
        REFERENCES customer (customer_id) ON DELETE CASCADE
);

CREATE INDEX idx_account_transactions_customer_id ON account_transactions (customer_id);
CREATE INDEX idx_account_transactions_account_number ON account_transactions (account_number);

INSERT INTO ACCOUNT_TRANSACTIONS
(transaction_id, account_number, customer_id, transaction_dt, transaction_summary, transaction_type,
 transaction_amt, closing_balance, create_dt)
VALUES (gen_random_uuid(), 186576453434, 1, CURRENT_DATE - INTERVAL '7 days', 'Coffee Shop', 'Withdrawal',
        30, 34500, CURRENT_DATE - INTERVAL '7 days');

INSERT INTO ACCOUNT_TRANSACTIONS
(transaction_id, account_number, customer_id, transaction_dt, transaction_summary, transaction_type,
 transaction_amt, closing_balance, create_dt)
VALUES (gen_random_uuid(), 186576453434, 1, CURRENT_DATE - INTERVAL '6 days', 'Uber', 'Withdrawal',
        100, 34500, CURRENT_DATE - INTERVAL '6 days');

INSERT INTO ACCOUNT_TRANSACTIONS
(transaction_id, account_number, customer_id, transaction_dt, transaction_summary, transaction_type,
 transaction_amt, closing_balance, create_dt)
VALUES (gen_random_uuid(), 186576453434, 1, CURRENT_DATE - INTERVAL '5 days', 'Self Deposit', 'Deposit',
        500, 34500, CURRENT_DATE - INTERVAL '5 days');

INSERT INTO ACCOUNT_TRANSACTIONS
(transaction_id, account_number, customer_id, transaction_dt, transaction_summary, transaction_type,
 transaction_amt, closing_balance, create_dt)
VALUES (gen_random_uuid(), 186576453434, 1, CURRENT_DATE - INTERVAL '4 days', 'Ebay', 'Withdrawal',
        600, 34500, CURRENT_DATE - INTERVAL '4 days');

INSERT INTO ACCOUNT_TRANSACTIONS
(transaction_id, account_number, customer_id, transaction_dt, transaction_summary, transaction_type,
 transaction_amt, closing_balance, create_dt)
VALUES (gen_random_uuid(), 186576453434, 1, CURRENT_DATE - INTERVAL '2 days', 'Online Transfer', 'Deposit',
        700, 34500, CURRENT_DATE - INTERVAL '2 days');

INSERT INTO ACCOUNT_TRANSACTIONS
(transaction_id, account_number, customer_id, transaction_dt, transaction_summary, transaction_type,
 transaction_amt, closing_balance, create_dt)
VALUES (gen_random_uuid(), 186576453434, 1, CURRENT_DATE - 1, 'Amazon.com', 'Withdrawal',
        100, 34500, CURRENT_DATE - 1);


create table loans
(
    loan_number        serial,
    customer_id        bigint       not null,
    start_dt           date         not null,
    loan_type          varchar(100) not null,
    total_loan         int          not null,
    amount_paid        int          not null,
    outstanding_amount int          not null,
    create_dt          date default null,
    constraint fk_customer foreign key (customer_id) references customer (customer_id) on delete cascade
);

create index idx_loans_customer_id on loans (customer_id);


INSERT INTO loans (customer_id, start_dt, loan_type, total_loan, amount_paid, outstanding_amount, create_dt)
VALUES (1, '2020-10-13', 'Home', 200000, 50000, 150000, '2020-10-13');

INSERT INTO loans (customer_id, start_dt, loan_type, total_loan, amount_paid, outstanding_amount, create_dt)
VALUES (1, '2020-06-06', 'Vehicle', 40000, 10000, 30000, '2020-06-06');

INSERT INTO loans (customer_id, start_dt, loan_type, total_loan, amount_paid, outstanding_amount, create_dt)
VALUES (1, '2018-02-14', 'Home', 50000, 10000, 40000, '2018-02-14');

INSERT INTO loans (customer_id, start_dt, loan_type, total_loan, amount_paid, outstanding_amount, create_dt)
VALUES (1, '2018-02-14', 'Personal', 10000, 3500, 6500, '2018-02-14');

create table cards
(
    card_id          serial primary key,
    card_number      varchar(100) not null,
    customer_id      bigint       not null,
    card_type        varchar(100) not null,
    total_limit      int          not null,
    amount_used      int          not null,
    available_amount int          not null,
    create_dt        date default null,
    constraint fk_customer foreign key (customer_id) references customer (customer_id) on delete cascade
);

create index idx_cards_customer_id on cards (customer_id);

create table notice_details
(
    notice_id      serial primary key,
    notice_summary varchar(200) not null,
    notice_details varchar(500) not null,
    notic_beg_dt   date         not null,
    notic_end_dt   date default null,
    create_dt      date default null,
    update_dt      date default null
);


INSERT INTO notice_details (notice_summary, notice_details, notic_beg_dt, notic_end_dt, create_dt, update_dt)
VALUES ('Home Loan Interest rates reduced',
        'Home loan interest rates are reduced as per the goverment guidelines. The updated rates will be effective immediately',
        current_date - INTERVAL '30 days', current_date + INTERVAL '30 days', current_date, null);

INSERT INTO notice_details (notice_summary, notice_details, notic_beg_dt, notic_end_dt, create_dt, update_dt)
VALUES ('Net Banking Offers',
        'Customers who will opt for Internet banking while opening a saving account will get a $50 amazon voucher',
        current_date - INTERVAL '30 days', current_date + INTERVAL '30 days', current_date, null);

INSERT INTO notice_details (notice_summary, notice_details, notic_beg_dt, notic_end_dt, create_dt, update_dt)
VALUES ('Mobile App Downtime',
        'The mobile application of the EazyBank will be down from 2AM-5AM on 12/05/2020 due to maintenance activities',
        current_date - INTERVAL '30 days', current_date + INTERVAL '30 days', current_date, null);

INSERT INTO notice_details (notice_summary, notice_details, notic_beg_dt, notic_end_dt, create_dt, update_dt)
VALUES ('E Auction notice',
        'There will be a e-auction on 12/08/2020 on the Bank website for all the stubborn arrears.Interested parties can participate in the e-auction',
        current_date - INTERVAL '30 days', current_date + INTERVAL '30 days', current_date, null);

INSERT INTO notice_details (notice_summary, notice_details, notic_beg_dt, notic_end_dt, create_dt, update_dt)
VALUES ('Launch of Millennia Cards',
        'Millennia Credit Cards are launched for the premium customers of EazyBank. With these cards, you will get 5% cashback for each purchase',
        current_date - INTERVAL '30 days', current_date + INTERVAL '30 days', current_date, null);

INSERT INTO notice_details (notice_summary, notice_details, notic_beg_dt, notic_end_dt, create_dt, update_dt)
VALUES ('COVID-19 Insurance',
        'EazyBank launched an insurance policy which will cover COVID-19 expenses. Please reach out to the branch for more details',
        current_date - INTERVAL '30 days', current_date + INTERVAL '30 days', current_date, null);

CREATE TABLE contact_messages
(
    contact_id    varchar(50)   NOT NULL,
    contact_name  varchar(50)   NOT NULL,
    contact_email varchar(100)  NOT NULL,
    subject       varchar(500)  NOT NULL,
    message       varchar(2000) NOT NULL,
    create_dt     date DEFAULT NULL,
    PRIMARY KEY (contact_id)
);

CREATE table authorities
(
    id          serial primary key,
    customer_id integer     not null,
    name        varchar(50) not null,
    constraint fk_customer foreign key (customer_id) references customer (customer_id)
);

create index idx_authorities_customer_id on authorities (customer_id);

insert into AUTHORITIES(customer_id, name)
values(1, 'VIEWACCOUNT');

insert into AUTHORITIES(customer_id, name)
values(1, 'VIEWCARD');

insert into AUTHORITIES(customer_id, name)
values(1, 'VIEWLOANS');

insert into AUTHORITIES(customer_id, name)
values(1, 'VIEWBALANCE');

delete from authorities;

insert into AUTHORITIES (customer_id, name)
values(1,'ROLE_USER');
insert into AUTHORITIES (customer_id, name)
values(1,'ROLE_ADMIN');