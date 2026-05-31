package net.proselyte.springsecuritydemo.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PermissionTest {

    @Test
    void developersRead_shouldHaveCorrectPermission() {
        assertEquals("developers:read", Permission.DEVELOPERS_READ.getPermission());
    }

    @Test
    void developersWrite_shouldHaveCorrectPermission() {
        assertEquals("developers:write", Permission.DEVELOPERS_WRITE.getPermission());
    }
}
