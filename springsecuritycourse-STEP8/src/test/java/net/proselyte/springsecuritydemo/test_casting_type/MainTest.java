package net.proselyte.springsecuritydemo.test_casting_type;

import org.junit.jupiter.api.Test;


/**
 * Приведение типов (casting) — это фраза компилятору:<br>
 * «Я знаю, что этот объект на самом деле является более конкретным типом. Поверь мне и дай доступ к его методам».<br>
 *
 * <p>
 * Пример для наглядности
 * <pre>{@code
 * public class Animal {
 *     public void eat() { System.out.println("ест"); }
 * }
 *
 *
 * public class Dog extends Animal {
 *     public void bark() { System.out.println("гав"); }
 * }
 * Animal a = new Dog();   // ВСЁГДА новый Dog, просто смотрим на него как на Animal
 * a.eat();                // ✅ есть у Animal
 * // a.bark();            // ❌ компилятор не видит — переменная типа Animal
 *
 * ((Dog) a).bark();       // ✅ кастуем — теперь видно bark()
 * }</pre>
 */
public class MainTest {

    @Test
    void test() {
        Animal a = new Dog();   // ВСЁГДА новый Dog, просто смотрим на него как на Animal
        a.eat();                // ✅ есть у Animal
        // a.bark();            // ❌ компилятор не видит — переменная типа Animal
        ((Dog) a).bark();       // ✅ кастуем — теперь видно bark()
    }
}
