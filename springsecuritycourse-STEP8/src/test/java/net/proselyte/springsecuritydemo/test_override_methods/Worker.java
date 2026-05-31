package net.proselyte.springsecuritydemo.test_override_methods;

public interface Worker {
    default void work(){
        System.out.println("Worker interface");
    }

    default void work_2() {
        System.out.println("Worker interface 2");
    }
}
