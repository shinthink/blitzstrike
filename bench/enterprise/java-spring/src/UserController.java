package com.example.controller;

import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    // VULNERABLE: SQL string concatenation of user input
    @GetMapping("/search")
    public String search(@RequestParam String q) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:postgresql://db/app");
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name LIKE '%" + q + "%'");
        return rs.getString(1);
    }

    // SAFE: PreparedStatement (parameterized)
    @GetMapping("/show")
    public String show(@RequestParam String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:postgresql://db/app");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ResultSet rs = ps.executeQuery();
        return rs.getString(1);
    }

    // VULNERABLE: command execution from user input
    @GetMapping("/export")
    public String export(@RequestParam String file) throws Exception {
        Runtime.getRuntime().exec("tar -czf /tmp/export.tar.gz " + file);
        return "ok";
    }
}
