CREATE TABLE users(
id SERIAL PRIMARY KEY,
name VARCHAR(50) NOT null,
email VARCHAR(255) NOT NULL UNIQUE,
password VARCHAR(255) NOT NULL,
about TEXT,
role INTEGER DEFAULT 0,
history VARCHAR [],
timestamp timestamp default current_timestamp
);

CREATE TABLE category(
id SERIAL PRIMARY KEY,
name VARCHAR(50) NOT null,
timestamp timestamp default current_timestamp
);

CREATE TABLE product(
id SERIAL PRIMARY KEY,
name VARCHAR(50) NOT null,
description TEXT NOT NULL,
price INTEGER NOT NULL,
quantity INTEGER NOT NULL,
sold INTEGER DEFAULT 0,
photo VARCHAR(255),
shipping BOOLEAN DEFAULT false,
category integer REFERENCES category (id),
timestamp timestamp default current_timestamp
);
