package net.proselyte.springsecuritydemo.test_override_methods;

// Класс с одним методом, который переопределяет дефолтный метод интерфейса.
public class Manager_V2 extends Employee_V2 implements Worker {

    @Override
    public void work_2() {
        System.out.println("Manager class");
    }
}
