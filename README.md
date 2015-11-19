## re2jitter

Основано на чудесном шаблоне Дениса https://github.com/pyos/re2jit-template/
Идея развита и доработана Александром Седовым.

### Что есть на настоящий момент?

JIT-компилятор, понимающий самую важную половину опкодов RE2. Пока не понимающий круглых скобочек и 
строк нулевой длины, но мы неизбежно работаем над этим.

JIT-компилятор работает только для x86-64, потому что использует всякую тёмную магию типа списков
указателей на код (что недоступно чудесной библиотеке libjit) и RIP-relative addressing
(что и не понадобилось бы, если честно, будь у нас 32-битная цель, потому что хранить 64-битные
указатели дюже неудобно и сложно, и приходится хранить сдвиги от начала кода). Зато код крутой
и позиционно независимый, вот.

