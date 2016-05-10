package main

import (
    "fmt"
    "github.com/realpg/ssgo/utils"
)

func initDatabase() int {
	tx,err:=db.Begin()
	if err!=nil {
		fmt.Printf("Error while initDatabase. transaction[%s]",err.Error())
		return 1
	}
	defer tx.Rollback()
	_,err = tx.Exec("DROP TABLE IF EXISTS ss_detail")
	if err!=nil {
		fmt.Printf("Error while initDatabase. droping detail [%s]",err.Error())
		return 1
	}
	_,err = tx.Exec("DROP TABLE IF EXISTS ss_admin")
	if err!=nil {
		fmt.Printf("Error while initDatabase. droping admin [%s]",err.Error())
		return 1
	}
	_,err = tx.Exec("DROP TABLE IF EXISTS ss_server")
	if err!=nil {
		fmt.Printf("Error while initDatabase. droping server [%s]",err.Error())
		return 1
	}
	_,err = tx.Exec("DROP TABLE IF EXISTS ss_user")
	if err!=nil {
		fmt.Printf("Error while initDatabase. droping user [%s]",err.Error())
		return 1
	}
	_,err = tx.Exec("CREATE TABLE `ss_admin` ( `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, `username` varchar(20) NOT NULL, `password` varchar(128) NOT NULL, PRIMARY KEY (`id`),UNIQUE KEY `username` (`username`) USING HASH) ENGINE=InnoDB DEFAULT CHARSET=utf8;")
	if err!=nil {
		fmt.Printf("Error while initDatabase. creating admin [%s]",err.Error())
		return 1
	}
	_,err = tx.Exec("CREATE TABLE `ss_server` ( `id` int(10) UNSIGNED NOT NULL, `name` varchar(20) NOT NULL, `addr` varchar(100) NOT NULL, PRIMARY KEY (`id`), UNIQUE KEY `name` (`name`)) ENGINE=InnoDB DEFAULT CHARSET=utf8;")
	if err!=nil {
		fmt.Printf("Error while initDatabase. creating server [%s]",err.Error())
		return 1
	}
	_,err = tx.Exec("CREATE TABLE `ss_user` ( `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, `name` varchar(20) NOT NULL, `email` varchar(200) NOT NULL, `password` varchar(128) NOT NULL, `port` smallint(5) UNSIGNED NOT NULL, `passwd` varchar(32) NOT NULL, `u` bigint(20) UNSIGNED NOT NULL, `d` bigint(20) NOT NULL, `ue` bigint(20) UNSIGNED NOT NULL, `de` bigint(20) UNSIGNED NOT NULL, `limits` bigint(20) UNSIGNED NOT NULL, `t` int(10) UNSIGNED NOT NULL, `active` tinyint(3) UNSIGNED NOT NULL, PRIMARY KEY (`id`),UNIQUE KEY `port` (`port`) USING BTREE, UNIQUE KEY `email` (`email`),KEY `active` (`active`) USING HASH) ENGINE=InnoDB DEFAULT CHARSET=utf8;")
	if err!=nil {
		fmt.Printf("Error while initDatabase. creating user [%s]",err.Error())
		return 1
	}
	_,err = tx.Exec("CREATE TABLE `ss_detail` ( `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, `server_id` int(10) UNSIGNED NOT NULL, `user_id` int(10) UNSIGNED NOT NULL, `u` bigint(20) UNSIGNED NOT NULL, `d` bigint(20) UNSIGNED NOT NULL, `ue` bigint(20) UNSIGNED NOT NULL, `de` bigint(20) UNSIGNED NOT NULL, `t` bigint(20) UNSIGNED NOT NULL, PRIMARY KEY (`id`),UNIQUE KEY `user_id` (`user_id`,`server_id`), KEY `sid01` (`server_id`), CONSTRAINT `sid01` FOREIGN KEY (`server_id`) REFERENCES `ss_server` (`id`), CONSTRAINT `uid01` FOREIGN KEY (`user_id`) REFERENCES `ss_user` (`id`) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8;")
	if err!=nil {
		fmt.Printf("Error while initDatabase. creating detail [%s]",err.Error())
		return 1
	}
	tx.Exec("INSERT INTO ss_admin (username,password) VALUES (?,?)","admin", utils.G("admin","admin123123"))
	err = tx.Commit()
	fmt.Println("Init database successfully! Exit!")
	return 0
}

func testAdmin(user,pass string) {
	utils.Test(user,pass)
}