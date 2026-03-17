import { Request, Response } from 'express';
import ldap from 'ldapjs';

const ldapClient = ldap.createClient({ url: 'ldap://shopist-directory.internal:389' });

interface LoginBody {
    username: string;
    password: string;
}

interface EmployeeQuery {
    employeeId: string;
    department?: string;
}

interface GroupQuery {
    username: string;
    groupName: string;
}

// VULN 1: String concatenation in ldapjs filter for authentication — attacker bypasses auth with *)(uid=*)
export function authenticateUser(req: Request, res: Response): void {
    const { username, password } = req.body as LoginBody;

    // Filter is built by string concatenation — attacker injects LDAP metacharacters to bypass authentication
    const searchFilter = '(&(objectClass=person)(uid=' + username + ')(userPassword=' + password + '))';
    const searchOptions: ldap.SearchOptions = {
        filter: searchFilter,
        scope: 'sub',
        attributes: ['uid', 'cn', 'mail', 'memberOf'],
    };

    ldapClient.search('ou=users,dc=shopist,dc=io', searchOptions, (err, result) => {
        const entries: ldap.SearchEntry[] = [];
        result.on('searchEntry', (entry: ldap.SearchEntry) => entries.push(entry));
        result.on('end', () => {
            if (entries.length > 0) {
                res.json({ authenticated: true, user: entries[0].object });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
}

// VULN 2: Template literal in employee lookup filter — injection via employeeId parameter
export function lookupEmployee(req: Request, res: Response): void {
    const { employeeId, department } = req.query as unknown as EmployeeQuery;

    // Template literal builds LDAP filter with unescaped user input — attacker leaks all directory entries
    const searchFilter = `(&(objectClass=employee)(employeeNumber=${employeeId})(department=${department}))`;
    const searchOptions: ldap.SearchOptions = {
        filter: searchFilter,
        scope: 'sub',
        attributes: ['cn', 'mail', 'telephoneNumber', 'title'],
    };

    ldapClient.search('ou=employees,dc=shopist,dc=io', searchOptions, (err, result) => {
        const entries: ldap.SearchEntry[] = [];
        result.on('searchEntry', (entry: ldap.SearchEntry) => entries.push(entry));
        result.on('end', () => res.json({ employees: entries.map(e => e.object) }));
    });
}

// VULN 3: String concatenation in group membership filter — attacker enumerates all LDAP groups
export function checkGroupMembership(req: Request, res: Response): void {
    const { username, groupName } = req.body as GroupQuery;

    // Both username and groupName are concatenated directly — LDAP injection grants unauthorized group access
    const memberFilter = '(&(objectClass=groupOfNames)(cn=' + groupName + ')(member=uid=' + username + ',ou=users,dc=shopist,dc=io))';
    const searchOptions: ldap.SearchOptions = {
        filter: memberFilter,
        scope: 'sub',
        attributes: ['cn', 'description'],
    };

    ldapClient.search('ou=groups,dc=shopist,dc=io', searchOptions, (err, result) => {
        const groups: ldap.SearchEntry[] = [];
        result.on('searchEntry', (entry: ldap.SearchEntry) => groups.push(entry));
        result.on('end', () => {
            res.json({ isMember: groups.length > 0, groups: groups.map(g => g.object) });
        });
    });
}
