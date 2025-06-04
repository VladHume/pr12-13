# pr12-13

## Мета роботи

Реалізувати програму на мові C для операційної системи FreeBSD, яка при виникненні фатального сигналу (наприклад, `SIGSEGV`) виконує автоматичний дамп усіх регістрів процесора (на архітектурі `x86_64`) у лог-файл.

## Теоретичні відомості

### Сигнали у Unix

Сигнали — це механізм взаємодії між процесами (IPC), що дозволяє надсилати асинхронні повідомлення процесам з боку ядра або інших процесів.

#### Основні характеристики:
- Асинхронні
- Мають числові і текстові назви (наприклад, `SIGSEGV`, `SIGINT`)
- Можуть бути перехоплені або проігноровані
- Мають типову поведінку за замовчуванням (kill, stop, ignore)


## [Реалізація](https://github.com/VladHume/pr12-13/blob/main/crash_handler.c)

### Опис програми

Програма встановлює обробник для критичних сигналів (`SIGSEGV`, `SIGILL`, `SIGFPE`, `SIGABRT`) за допомогою `sigaction()`.

Коли програма аварійно завершується, виводиться дамп регістрів у файл `crash.log`.

### Ключові частини коду:

#### Встановлення обробника сигналів:
```c
struct sigaction sa;
memset(&sa, 0, sizeof(sa));
sa.sa_sigaction = signal_handler;
sa.sa_flags = SA_SIGINFO;
sigaction(SIGSEGV, &sa, NULL);
sigaction(SIGILL, &sa, NULL);
sigaction(SIGFPE, &sa, NULL);
sigaction(SIGABRT, &sa, NULL);
```

#### Обробка сигналу:
```c
void signal_handler(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
    FILE *log = fopen("crash.log", "a");
    // запис регістрів з ucontext_t у файл
    fclose(log);
    _Exit(1);
}
```

#### Дамп регістрів (приклад для x86_64):
```c
fprintf(log, "RIP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rip);
fprintf(log, "RSP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rsp);
// ... інші регістри
```

### Компіляція
```sh
gcc -Wall -o crash_handler crash_handler.c
```

### Приклад запуску
```c
int *ptr = NULL;
*ptr = 42; // Викличе SIGSEGV
```
Після аварії зʼявиться файл crash.log, у якому буде вміст регістрів на момент падіння.

### Вивід (crash.log)
![image](https://github.com/user-attachments/assets/c3f1dc42-c04d-497e-bf3f-c4fa8d4c5348)

## Висновки

- Реалізовано обробку фатальних сигналів.
- Програма виконує дамп регістрів на момент падіння.
- Такий підхід корисний для налагодження та збору інформації про причину збою.
