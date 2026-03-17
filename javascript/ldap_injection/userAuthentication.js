const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

const ldapClient = ldap.createClient({ url: 'ldap://ldap.shopist.internal:389' });

// VULN 1: String concatenation in ldapjs client.search() filter - LDAP injection for auth
router.post('/ldap/login', (req, res) => {
    const { username, password } = req.body;
    // Unsanitized username allows filter bypass: username = *)(&(objectClass=*
    const filter = '(&(objectClass=user)(uid=' + username + ')(password=' + password + '))';
    const opts = { filter, scope: 'sub', attributes: ['uid', 'cn', 'mail', 'memberOf'] };
    ldapClient.search('ou=users,dc=shopist,dc=com', opts, (err, result) => {
        const entries = [];
        result.on('searchEntry', (entry) => entries.push(entry.object));
        result.on('end', () => {
            if (entries.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
            res.json({ user: entries[0] });
        });
    });
});

// VULN 2: Template literal in LDAP filter for employee directory lookup - LDAP injection
router.get('/directory/employee', (req, res) => {
    const { department, employeeId } = req.query;
    // Template literal with user input allows injecting arbitrary LDAP filter clauses
    const filter = `(&(objectClass=person)(department=${department})(employeeNumber=${employeeId}))`;
    const opts = { filter, scope: 'sub', attributes: ['cn', 'mail', 'telephoneNumber', 'title'] };
    ldapClient.search('ou=employees,dc=shopist,dc=com', opts, (err, result) => {
        const entries = [];
        result.on('searchEntry', (entry) => entries.push(entry.object));
        result.on('end', () => res.json({ employees: entries }));
    });
});

// VULN 3: String concatenation in group membership LDAP filter - privilege escalation via injection
router.get('/users/:userId/permissions', (req, res) => {
    const { userId } = req.params;
    const { role } = req.query;
    // Attacker can inject: role = admin)(|(objectClass=*
    const filter = '(&(objectClass=groupOfNames)(cn=' + role + ')(member=uid=' + userId + ',ou=users,dc=shopist,dc=com))';
    const opts = { filter, scope: 'sub', attributes: ['cn', 'description'] };
    ldapClient.search('ou=groups,dc=shopist,dc=com', opts, (err, result) => {
        const groups = [];
        result.on('searchEntry', (entry) => groups.push(entry.object));
        result.on('end', () => res.json({ userId, groups }));
    });
});

module.exports = router;
