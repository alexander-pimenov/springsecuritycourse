package net.proselyte.springsecuritydemo.test_override_methods;

import org.junit.jupiter.api.Test;

/**
 * Задача проверить, что выведется в консоль:
 * - Employee class
 * - Worker interface
 * - Compilation error
 * - Runtime error
 * <p>Как увидим из теста, выведется "Employee class".
 * Почему?
 * <p>Потому что:<br>
 * 1. Иерархия классов важнее интерфейсов<br>
 * В Java при наследовании действует простое правило: <b>класс всегда имеет приоритет над интерфейсом</b>.
 * Конкретные методы из классов имеют абсолютный приоритет над default-методами интерфейсов.</b>
 * В спецификации Java (JLS §9.4.1.3) сказано: "default methods are overridden by concrete methods in superclasses"<br>
 * Даже если интерфейс предоставляет default-метод. У класса Employee есть конкретный метод work().
 * При наследовании класс Manager получает этот метод напрямую от родителя.<br>
 * 2. Механизм разрешения конфликтов в Java<br>
 * Когда Java встречает вызов метода manager.work(), она ищет метод в таком порядке:<br>
 * - Самый приоритетный - конкретные методы в самом классе (Manager)<br>
 * - Конкретные методы в суперклассах (поднимается вверх по иерархии) - здесь находится Employee.work()<br>
 * - Default-методы интерфейсов - только если метод не найден в классах<br>
 * 3. Почему не возникает конфликта?</b>
 * Многие думают, что здесь конфликт между:<br>
 * - Employee.work() (класс)<br>
 * - Worker.work() (default-метод интерфейса)<br>
 * Но конфликта нет, потому что:<br>
 * - Manager наследует конкретную реализацию от Employee<br>
 * - Worker предоставляет только default-реализацию<br>
 * <b>Конкретные методы из классов всегда переопределяют default-методы интерфейсов<b><br>
 * 4. Это сделано специально для обратной совместимости - чтобы добавление default-методов в интерфейсы не ломало существующий код, который уже имеет методы с такими же сигнатурами в классах-предках.
 * 5. Что произойдет, если будет два интерфейса с default-методами?<br>
 * <pre>
 * {@code
 * interface Worker { default void work() {...} }
 * interface Sleeper { default void work() {...} }
 *
 * // А вот здесь будет КОНФЛИКТ!
 * class Manager extends Employee implements Worker, Sleeper {
 *     // Нужно обязательно переопределить work()
 *     @Override
 *     public void work() {
 *         Worker.super.work();  // или свой вариант
 *     }
 * }
 * }</pre>
 *
 */
public class MainTest {
    /**
     * Java находит метод в Employee на втором шаге поиска (после проверки самого класса)<br>
     * Поиск останавливается, и default-метод из интерфейса даже не рассматривается<br>
     */
    @Test
    void runTest_1() {
        Manager manager = new Manager();
        manager.work(); //Employee class
    }

    /**
     * В этом варианте метод work() нет в Employee_V2.
     * Тогда Manager_V2 использует Worker.work().
     * А также Manager_V2 переопределил метод work_2 и поэтому,
     * согласно высокого приоритета берется метод класса, а не дефолтного метода интерфейса.
     */
    @Test
    void runTest_2() {
        Manager_V2 manager = new Manager_V2();
        manager.work();    //"Worker interface"
        manager.work_2();  //"Manager class" (самый высокий приоритет)
    }
}
