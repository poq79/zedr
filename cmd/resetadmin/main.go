// resetadmin — 管理员密码重置工具（忘记密码恢复场景）。
//
// 场景：唯一管理员忘记密码。初始密码由首次启动随机生成且只打印一次，
// 旧日志丢失后无法找回（库中仅存 bcrypt 哈希）——此时由本机管理员
// 在服务器本地运行本工具重置。
//
// 安全模型：工具需要直接读写服务端 SQLite 文件，等价于本机管理员权限；
// 它不提供远程/提权能力，不绕过任何网络边界。
//
// 用法：
//
//	resetadmin                          # 交互缺失时列出账号并退出
//	resetadmin -new '新密码'            # 重置唯一管理员（role=admin）密码
//	resetadmin -generate                # 随机生成 14 位强密码并打印
//	resetadmin -db ./data/zedr-server.db -new 'xxx'
//
// 重置语义与 ChangePassword 一致：同步吊销该用户全部刷新令牌。
package main

import (
	"crypto/rand"
	"database/sql"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^*-_=+"

func main() {
	dbPath := flag.String("db", "./data/zedr-server.db", "服务端 SQLite 路径（与 HG_SERVER_DB_PATH 一致）")
	newPw := flag.String("new", "", "新密码（≥8 位）")
	generate := flag.Bool("generate", false, "随机生成 14 位强密码")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		fatal("打开数据库失败: %v", err)
	}
	defer db.Close()

	admin, err := findAdmin(db)
	if err != nil {
		fatal("%v", err)
	}
	if *newPw == "" && !*generate {
		fmt.Println("未指定 -new / -generate，仅列出账号：")
		listUsers(db)
		fmt.Printf("\n用法: resetadmin -db %s (-new '新密码' | -generate)\n", *dbPath)
		return
	}

	pw := *newPw
	if *generate {
		pw, err = genPassword(14)
		if err != nil {
			fatal("生成密码失败: %v", err)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		fatal("哈希失败: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		fatal("开启事务失败: %v", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(hash), admin.id); err != nil {
		fatal("更新密码失败: %v", err)
	}
	// TOTP 一并解除（迁移 012）：忘记密码的典型场景往往是设备也丢了
	//（换机/重装/认证器迁移失败），此时只改密码不清 TOTP，管理员依旧
	// 进不了控制台——恢复工具必须打通整条登录链。
	// 列可能不存在（老库未跑迁移 012）：用 UPDATE 宽松容错，失败仅提示。
	mfaCleared := true
	if _, err := tx.Exec(`UPDATE users SET totp_secret='', totp_enabled=0 WHERE id=?`, admin.id); err != nil {
		mfaCleared = false
	}
	// 与 ChangePassword 相同的轮换语义：改密即吊销全部刷新令牌。
	res, err := tx.Exec(`DELETE FROM refresh_tokens WHERE user_id=?`, admin.id)
	revoked := int64(-1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: 吊销刷新令牌失败（表可能为空）: %v\n", err)
	} else {
		revoked, _ = res.RowsAffected()
	}
	if err := tx.Commit(); err != nil {
		fatal("提交失败: %v", err)
	}

	fmt.Printf("OK: 已重置管理员 %s 的密码，并吊销 %d 个刷新令牌。\n", admin.username, revoked)
	if mfaCleared {
		fmt.Println("已同时解除该账号的双因素验证绑定（TOTP）。")
	}
	fmt.Printf("新密码: %s\n", pw)
	fmt.Println("请立即登录管理台并在「修改密码」中更换为自己的密码。")
}

type account struct {
	id, username, role string
}

func findAdmin(db *sql.DB) (account, error) {
	rows, err := db.Query(`SELECT id, username, role FROM users`)
	if err != nil {
		return account{}, err
	}
	defer rows.Close()
	var admins []account
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.id, &a.username, &a.role); err != nil {
			return account{}, err
		}
		if a.role == "admin" {
			admins = append(admins, a)
		}
		fmt.Printf("  账号: %-16s 角色: %s\n", a.username, a.role)
	}
	if len(admins) == 0 {
		return account{}, fmt.Errorf("库中没有 admin 角色账号")
	}
	if len(admins) > 1 {
		fmt.Fprintf(os.Stderr, "warn: 存在 %d 个管理员，将重置第一个（%s）\n", len(admins), admins[0].username)
	}
	return admins[0], nil
}

func listUsers(db *sql.DB) {
	rows, err := db.Query(`SELECT username, role FROM users ORDER BY username`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var u, r string
		_ = rows.Scan(&u, &r)
		fmt.Printf("  %-16s %s\n", u, r)
	}
}

// genPassword 生成无歧义字符（去掉 I l 1 O 0 等）的强密码，
// 保证四类字符各至少 1 个。
func genPassword(n int) (string, error) {
	if n < 8 {
		n = 14
	}
	groups := []func(byte) bool{
		func(c byte) bool { return c >= 'A' && c <= 'Z' },
		func(c byte) bool { return c >= 'a' && c <= 'z' },
		func(c byte) bool { return c >= '0' && c <= '9' },
		func(c byte) bool { return strings.ContainsRune("!@#$%^*-_=+", rune(c)) },
	}
	for attempts := 0; attempts < 100; attempts++ {
		b := make([]byte, n)
		for i := range b {
			k, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return "", err
			}
			b[i] = charset[k.Int64()]
		}
		ok := true
		for _, in := range groups {
			found := false
			for _, c := range b {
				if in(c) {
					found = true
					break
				}
			}
			if !found {
				ok = false
				break
			}
		}
		if ok {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("生成失败")
}

func fatal(f string, v ...any) {
	fmt.Fprintf(os.Stderr, "resetadmin: "+f+"\n", v...)
	os.Exit(1)
}
