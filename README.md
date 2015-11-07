## re2jit

Как-то так.

### На чем это собирать?

На 64-битном линуксе. Наверное, можно и на Mac OS X. Под Windows нельзя.

### А что вообще сделать нужно?

Реализовать методы `match` у объекта `re2jit::native` в файлах it.vm.cc
и it.x64.cc.

### Чудо-Makefile

```bash
make  # собрать и выполнить тесты
make test  # то же самое
make test/10-literal  # один конкретный тест
make test/30-long test/31-unicode  # или несколько
make obj/libre2jit.a  # просто собрать статическую библиотеку
make obj/libre2jit.so  # или динамическую
make clean  # удалить все скомпилированные файлы
```

Ко всем этим командам можно дописать `ENABLE_VM=1` чтобы вместо jit-компилятора
использовать виртуальную машину. `ENABLE_PERF_TESTS=1` включает тесты
производительности, но их еще придумать надо.

#### Как добавлять новые файлы с кодом

Новые заголовочные файлы надо дописывать в массив `_require_headers` в Makefile.
Файлы с кодом дописывать не надо; вместо этого для каждого файла `re2jit/*.cc`
должна быть запись с соответствующим ему объектным файлом `obj/*.o`
в `_require_objects`.

**make чувствителен к табуляции**. Если редактор автоматически заменяет табы на пробелы,
перед редактированием Makefile эту функцию обязательно отключить. Нельзя ставить 4 пробела,
2 пробела, 8 пробелов - надо именно табы. Если `make` говорит что-то вроде
`*** missing separator. stop.`, то стоит перестать считать себя умнее make и начать
выполнять инструкции.

#### Как писать тесты

Каждый набор тестов состоит из 2 файлов.

  * `xx-test.cc` -- описания самих тестов в формате `test_case(name) { whatever; }`.
    `name` должно быть константной строкой, `whatever` - произвольным кодом.
    Успешно выполненный тест возвращает `true` или `Result::Pass("сообщение")`.
    Проваленный - `false` или `Result::Fail("...")`. Пропущенный - `Result::Skip("...")`.
    Сообщение обязательно; синтаксис у него как у printf - например, можно вернуть
    `Result::Fail("expected %d, got %d", expect, result)`.

  * `xx-test.h` -- просто заголовочный файл, который подключается во время компиляции теста.
    Если тест использует дополнительные библиотеки, их можно объявить в начале этого файла
    в таком виде: `//! library: someexternallibrary`.

Созданный тест всегда можно выполнить по `make test/xx-test`. Если хочется, чтобы
он выполнялся и по `make test`, его надо дописать в массив `_require_test_run`
в Makefile.

В файле `00-definitions.h` объявлены несколько макросов - стандартных реализаций тестов.
(anchor - либо UNANCHORED, либо ANCHOR_START, либо ANCHOR_END.)

```c++
FIXED_TEST("регулярка", anchor, "ввод", true/false, /* если true, тут можно перечислить
                                                       что должны были заматчить группы */);
// сама регулярка тоже считается группой, т.е. первой строкой после true
// должно быть написано что заматчила вся регулярка. можно ничего не писать,
// тогда проверится только ответ.


// Это как FIXED_TEST, только правильный ответ определяется запуском re2 на том же вводе.
MATCH_TEST("регулярка", anchor, "ввод", 0 /* количество групп, содержимое которых
                                             надо проверить. */);


// Без ENABLE_PERF_TESTS=1 это то же самое, что и MATCH_TEST. С флагом же
// в дополнение к проверке результата выводится сколько времени нужно чтобы
// выполнить re2::Match с такими данными n раз, а сколько - re2jit::match.
MATCH_PERF_TEST(n, /* остальные аргументы как у MATCH_TEST */);


// Это как MATCH_PERF_TEST, только выводит в терминал не регулярку и ввод,
// а заданную строку. На случай если захочется потестировать на больших данных.
MATCH_PERF_TEST_NAMED("название теста", /* остальные аргументы как у MATCH_PERF_TEST */);
```
