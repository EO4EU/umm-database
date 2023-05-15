-- creation.sql

-- Create a new database named "mydatabase"
CREATE DATABASE mydatabase;

-- Connect to the "mydatabase" database
\c mydatabase;

-- Create a table called "users" with an id and name column
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL
);

-- Insert some sample data into the table
INSERT INTO users (name) VALUES ('Alice'), ('Bob'), ('Charlie');