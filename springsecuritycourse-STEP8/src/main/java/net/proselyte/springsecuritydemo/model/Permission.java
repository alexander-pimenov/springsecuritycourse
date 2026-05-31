package net.proselyte.springsecuritydemo.model;

/**
 * Для гибкости системы можно каждой роли присваивать полномоция (пермишены).
 */
public enum Permission {
    //те кто имеет полномочия на чтение
    DEVELOPERS_READ("developers:read"),
    //те кто имеет полномочия на запись
    DEVELOPERS_WRITE("developers:write");

    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
