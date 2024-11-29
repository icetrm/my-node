CREATE DATABASE IF NOT EXISTS `ecom` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

USE `ecom`;

CREATE TABLE IF NOT EXISTS `role` (
    `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `title` VARCHAR(50) NOT NULL,
    `create_author` VARCHAR(100) NOT NULL,
    `create_date` DATETIME NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS `user` (
    `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `first_name` VARCHAR(150) NOT NULL,
    `last_name` VARCHAR(150) NOT NULL,
    `mobile` VARCHAR(20) NOT NULL,
    `email` VARCHAR(50) NOT NULL,
    `gender` VARCHAR(10) NOT NULL,
    `age` INT NOT NULL,
    `last_login` DATETIME NULL,
    `create_author` VARCHAR(50) NOT NULL,
    `create_date` DATETIME NOT NULL DEFAULT NOW(),
    `update_author` VARCHAR(50) NULL,
    `update_date` DATETIME NULL,
    `role_id` BIGINT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES role(id)
);

CREATE TABLE IF NOT EXISTS `category` (
    `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL,
    `create_author` VARCHAR(50) NOT NULL,
    `create_date` DATETIME NOT NULL DEFAULT NOW(),
    `update_author` VARCHAR(50) NULL,
    `update_date` DATETIME NULL
);

CREATE TABLE IF NOT EXISTS `product` (
  `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(150) NOT NULL,
  `description` VARCHAR(255) NULL,
  `price` DOUBLE NOT NULL DEFAULT 0,
  `discount_percentage` DOUBLE NOT NULL DEFAULT 0,
  `rating` DOUBLE NOT NULL DEFAULT 0,
  `stock` BIGINT NOT NULL DEFAULT 0,
  `brand` VARCHAR(255) NULL,
  `category_id` BIGINT NOT NULL,
  `create_author` VARCHAR(50) NOT NULL,
  `create_date` DATETIME NOT NULL DEFAULT NOW(),
  `update_author` VARCHAR(50) NULL,
  `update_date` DATETIME NULL,
  FOREIGN KEY (category_id) REFERENCES category(id)
);


INSERT INTO role (title, create_author) VALUES ('admin', 'system');
INSERT INTO role (title, create_author) VALUES ('guest', 'system');

INSERT INTO `user` (`username`, `password`, `first_name`, `last_name`, `mobile`, `email`, `gender`, `age`, `role_id`, `create_author`) VALUES
('admin', '$2a$12$wVdmouWca7GPgB6m75vQMO1Rv3cPiPoGuGdjkw8jlgpkM2JAGn9OK', 'ธีรเมธ', 'บุญรอด', '0882805014', 'th@gmail.com', 'M', 20, 1, 'SYSTEM'),
('guest', '$2a$12$wVdmouWca7GPgB6m75vQMO1Rv3cPiPoGuGdjkw8jlgpkM2JAGn9OK', 'อนุสร', 'สถาน', '088280xxxx', 'th@gmail.com', 'M', 30, 2, 'SYSTEM');

INSERT INTO `category` (`name`, `create_author`) VALUES
('smartphones', 'SYSTEM'),
('laptops', 'SYSTEM'),
('fragrances', 'SYSTEM'),
('skincare', 'SYSTEM'),
('groceries', 'SYSTEM'),
('home-decoration', 'SYSTEM'),
('furniture', 'SYSTEM'),
('tops', 'SYSTEM'),
('womens-dresses', 'SYSTEM'),
('womens-shoes', 'SYSTEM'),
('mens-shirts', 'SYSTEM'),
('mens-shoes', 'SYSTEM'),
('mens-watches', 'SYSTEM'),
('womens-watches', 'SYSTEM'),
('womens-bags', 'SYSTEM'),
('womens-jewellery', 'SYSTEM'),
('sunglasses', 'SYSTEM'),
('automotive', 'SYSTEM'),
('motorcycle', 'SYSTEM'),
('lighting', 'SYSTEM');

INSERT INTO `product` (`title`,`description`,`price`,`discount_percentage`,`rating`,`stock`,`brand`,`category_id`,`create_author`) VALUES
('iPhone 9','An apple mobile which is nothing like apple',549,12.96,4.69,94,'Apple',1,'SYSTEM');