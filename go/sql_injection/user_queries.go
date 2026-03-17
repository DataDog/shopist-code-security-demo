package sqlinjection

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

var db *sql.DB

// VULN 1: fmt.Sprintf SQL injection - login
func AuthenticateUser(username, password string) (*User, error) {
	query := fmt.Sprintf(
		"SELECT * FROM users WHERE username = '%s' AND password = '%s'",
		username, password,
	)
	row := db.QueryRow(query)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role)
	return &u, err
}

// VULN 2: String concatenation SQL injection - profile lookup
func GetUserProfile(userID string) (*User, error) {
	query := "SELECT id, name, email, role FROM users WHERE id = " + userID
	row := db.QueryRow(query)
	var u User
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.Role)
	return &u, err
}

// VULN 3: fmt.Sprintf with LIKE - admin user search
func SearchUsersAdmin(searchTerm string) ([]User, error) {
	query := fmt.Sprintf(
		"SELECT id, username, email, role FROM users WHERE username LIKE '%%%s%%' OR email LIKE '%%%s%%'",
		searchTerm, searchTerm,
	)
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role)
		users = append(users, u)
	}
	return users, nil
}
