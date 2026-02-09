using System;
using System.IO;
using System.Net;
using System.Data;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Npgsql;
using Renci.SshNet;

namespace MainTaskFinder
{
    class Program
    {
        private static readonly string SessionDir = Path.Combine(AppContext.BaseDirectory, "session");
        private static readonly string CredentialsFile = Path.Combine(SessionDir, "credentials.dat");

        private static ForwardedPortLocal _sshPortForward;
        private static SshClient _sshClient;
        private static NpgsqlConnection _dbConnection;
        private static int _localTunnelPort = 0;

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("🔍 DirectumRX MainTask finder\n");

            try
            {
                // Пробуем загрузить сессию для использования как дефолтов
                ConnectionCredentials? lastSession = null;
                bool sessionValid = false;

                if (File.Exists(CredentialsFile))
                {
                    try
                    {
                        lastSession = LoadCredentials();
                        sessionValid = true;
                        Console.WriteLine($"💡 Найдена последняя сессия: БД={lastSession.DbHost}:{lastSession.DbPort}\n");
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"⚠️ Сохранённая сессия повреждена: {ex.Message}\n");
                        Console.ResetColor();
                        lastSession = null;
                    }
                }

                ConnectionCredentials creds;

                // Если сессия валидна — спрашиваем, использовать ли её напрямую
                if (sessionValid == true)
                {
                    Console.Write("Подключиться к последней сессии? (да/нет) [да]: ");
                    string answer = Console.ReadLine()?.Trim().ToLower() ?? "да";

                    if (answer == "да" || answer == "д" || answer == "yes" || answer == "y" || answer == "1" || string.IsNullOrEmpty(answer))
                    {
                        creds = lastSession!;
                        Console.WriteLine("\n✅ Использую сохранённые параметры подключения\n");
                    }
                    else
                    {
                        // Пользователь отказался — запрашиваем данные, но с дефолтами из сессии
                        creds = PromptConnectionDetails(lastSession);
                    }
                }
                else
                {
                    // Сессии нет или она битая — запрашиваем с хардкодными дефолтами
                    creds = PromptConnectionDetails(null);
                }

                // Устанавливаем соединение
                Cleanup();
                SetupConnection(creds);

                // Сохраняем успешную сессию (только оригинальные данные!)
                try
                {
                    Directory.CreateDirectory(SessionDir);
                    SaveCredentials(creds);
                    Console.WriteLine("\n✅ Данные подключения сохранены локально (зашифрованы под вашей учётной записью Windows)");
                    Console.WriteLine($"📁 Файл: {CredentialsFile}");
                    Console.WriteLine("💡 Чтобы очистить сессию — введите 'очистить' в поле ссылки или удалите папку 'session'\n");
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"\n⚠️ Не удалось сохранить сессию: {ex.Message}\n");
                    Console.ResetColor();
                }

                RunDebuggerLoop();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n❌ Критическая ошибка: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"Детали: {ex.InnerException.Message}");
                Console.ResetColor();
                Console.WriteLine("\nНажмите любую клавишу для выхода...");
                Console.ReadKey();
            }
            finally
            {
                Cleanup();
            }
        }

        // Умный ввод с дефолтами из сессии ИЛИ хардкодными значениями
        static ConnectionCredentials PromptConnectionDetails(ConnectionCredentials? defaults)
        {
            Console.WriteLine("⚙️ Настройка подключения к БД");

            // Дефолтные значения: из сессии → хардкод
            string defSshHost = defaults?.SshHost ?? "";
            int defSshPort = defaults?.SshPort ?? 22;
            string defSshUser = defaults?.SshUser ?? "";
            string defSshPass = defaults?.SshPassword ?? "";
            string defDbHost = defaults?.DbHost ?? "";
            int defDbPort = defaults?.DbPort ?? 5432;
            string defDbName = defaults?.DbName ?? "";
            string defDbUser = defaults?.DbUser ?? "";
            string defDbPass = defaults?.DbPassword ?? "";

            string useSsh = ReadWithDefault("Подключаться через SSH?", defaults?.UseSsh == true ? "да" : "нет").ToLower();
            bool sshRequired = useSsh == "да" || useSsh == "yes" || useSsh == "y" || useSsh == "1" || useSsh == "д" || string.IsNullOrEmpty(useSsh);

            string sshHost = sshRequired ? ReadWithDefault("SSH хост", defSshHost) : "";
            int sshPort = sshRequired ? int.Parse(ReadWithDefault("SSH порт", defSshPort.ToString())) : 22;
            string sshUser = sshRequired ? ReadWithDefault("SSH пользователь", defSshUser) : "";
            string sshPassword = sshRequired ? ReadPassword("SSH пароль", defSshPass) : "";

            string dbHost = ReadWithDefault("Хост БД", sshRequired ? defDbHost : "localhost");
            int dbPort = int.Parse(ReadWithDefault("Порт БД", defDbPort.ToString()));
            string dbName = ReadWithDefault("Имя БД", defDbName);
            string dbUser = ReadWithDefault("Пользователь БД", defDbUser);
            string dbPassword = ReadPassword("Пароль БД", defDbPass);

            return new ConnectionCredentials
            {
                UseSsh = sshRequired,
                SshHost = sshHost,
                SshPort = sshPort,
                SshUser = sshUser,
                SshPassword = sshPassword,
                DbHost = dbHost,
                DbPort = dbPort,
                DbName = dbName,
                DbUser = dbUser,
                DbPassword = dbPassword
            };
        }

        static string ReadWithDefault(string prompt, string defaultValue)
        {
            Console.Write($"{prompt} [{defaultValue}]: ");
            string input = Console.ReadLine()?.Trim();
            return string.IsNullOrEmpty(input) ? defaultValue : input;
        }

        // Безопасный ввод пароля с поддержкой дефолтного значения
        static string ReadPassword(string prompt, string defaultMask = "*************")
        {
            Console.Write($"{prompt} [{defaultMask}]: ");

            // Считываем символы без эха
            StringBuilder password = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    // Если ничего не ввели — возвращаем дефолт (но только если маска не "*************")
                    if (password.Length == 0 && defaultMask != "*************")
                    {
                        // Хитрость: дефолтный пароль мы не храним в открытом виде в интерфейсе,
                        // поэтому если пользователь нажал Enter — возвращаем пустую строку,
                        // а реальный дефолт будет взят из объекта сессии выше по стеку
                        return "";
                    }
                    return password.ToString();
                }
                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Length--;
                    Console.Write("\b \b");
                }
                else if (key.Key != ConsoleKey.Backspace)
                {
                    password.Append(key.KeyChar);
                    Console.Write('*');
                }
            }
        }

        static void SetupConnection(ConnectionCredentials creds)
        {
            string actualDbHost = creds.DbHost;
            int actualDbPort = creds.DbPort;

            if (creds.UseSsh)
            {
                Console.WriteLine($"\n-- Устанавливаю SSH-соединение к {creds.SshHost}:{creds.SshPort}...");
                _sshClient = new SshClient(creds.SshHost, creds.SshPort, creds.SshUser, creds.SshPassword);
                _sshClient.Connect();
                Console.WriteLine($"-- SSH-соединение установлено к {creds.SshHost}:{creds.SshPort}");

                // Подбираем свободный локальный порт
                _localTunnelPort = FindFreeLocalPort(54321, 54400);
                _sshPortForward = new ForwardedPortLocal("127.0.0.1", (uint)_localTunnelPort, creds.DbHost, (uint)creds.DbPort);
                _sshClient.AddForwardedPort(_sshPortForward);
                _sshPortForward.Start();

                Console.WriteLine($"-- SSH-туннель: 127.0.0.1:{_localTunnelPort} ⇄ {creds.DbHost}:{creds.DbPort}");

                actualDbHost = "127.0.0.1";
                actualDbPort = _localTunnelPort;
            }

            Console.WriteLine("\n-- Подключаюсь к БД...");
            var connStrBuilder = new NpgsqlConnectionStringBuilder
            {
                Host = actualDbHost,
                Port = actualDbPort,
                Database = creds.DbName,
                Username = creds.DbUser,
                Password = creds.DbPassword,
                CommandTimeout = 30
            };

            _dbConnection = new NpgsqlConnection(connStrBuilder.ToString());
            _dbConnection.Open();
            Console.WriteLine("-- Подключение к БД установлено ✅\n");
        }

        static int FindFreeLocalPort(int startPort, int endPort)
        {
            for (int port = startPort; port <= endPort; port++)
            {
                try
                {
                    using (var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp))
                    {
                        socket.Bind(new IPEndPoint(IPAddress.Loopback, port));
                        return port;
                    }
                }
                catch
                {
                    continue;
                }
            }
            throw new Exception($"Не найдено свободных портов в диапазоне {startPort}-{endPort}");
        }

        static void RunDebuggerLoop()
        {
            while (true)
            {
                try
                {
                    Console.WriteLine("\nВведите ссылку на задачу/задание (или 'выход' для завершения, 'очистить' для сброса сессии):");
                    Console.Write("> ");
                    string url = Console.ReadLine()?.Trim();

                    if (string.IsNullOrEmpty(url) || url.ToLower() == "выход" || url.ToLower() == "exit")
                        break;

                    if (url.ToLower() == "очистить" || url.ToLower() == "clear")
                    {
                        if (File.Exists(CredentialsFile))
                        {
                            File.Delete(CredentialsFile);
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n✅ Сессия очищена. При следующем запуске потребуется ввести данные заново.");
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.WriteLine("\nℹ️ Активная сессия не найдена.");
                        }
                        continue;
                    }

                    var idMatch = Regex.Match(url, @"/(\d+)$");
                    var discrMatch = Regex.Match(url, @"card/([0-9a-fA-F\-]{36})");

                    if (!idMatch.Success || !discrMatch.Success)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("⚠️ Не удалось извлечь ID или Discriminator из ссылки. Проверьте формат.");
                        Console.ResetColor();
                        continue;
                    }

                    long assignmentId = long.Parse(idMatch.Groups[1].Value);
                    Guid discriminator = Guid.Parse(discrMatch.Groups[1].Value);

                    Console.WriteLine($"\n🔍 Извлечено: ID={assignmentId}, Discriminator={discriminator}\n");

                    FindRootTask(assignmentId, discriminator);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\n❌ Ошибка при обработке: {ex.Message}");
                    if (ex.InnerException != null)
                        Console.WriteLine($"Детали: {ex.InnerException.Message}");
                    Console.ResetColor();
                }

                Console.WriteLine("\nНажмите любую клавишу для нового поиска (или Esc для выхода)...");
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Escape)
                    break;
            }
        }

        static void FindRootTask(long startId, Guid discriminator)
        {
            long currentId = startId;
            string currentTable = "assignment";
            int iteration = 0;
            const int maxIterations = 100;

            Console.WriteLine("🚀 Запуск алгоритма поиска корневой задачи...\n");

            // ШАГ 1: Проверка задания
            Console.WriteLine($"[Шаг 1] Проверяю задание ID={currentId}");
            var (hasTask, taskId) = CheckAssignment(currentId, discriminator);

            if (hasTask && taskId.HasValue)
            {
                currentId = taskId.Value;
                currentTable = "task";
                Console.WriteLine($"→ Найдена связанная задача: ID={currentId}\n");
            }
            else
            {
                Console.WriteLine($"→ Задание не содержит ссылки на задачу. Проверяю таблицу задач напрямую...");
                var (hasParent, parentTaskId, parentAsgId) = CheckTask(currentId, discriminator);

                if (!hasParent)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("\n⚠️ Не найдено родительских элементов. Невозможно определить корневую задачу.");
                    Console.ResetColor();
                    return;
                }

                if (parentTaskId.HasValue)
                {
                    currentId = parentTaskId.Value;
                    currentTable = "task";
                    Console.WriteLine($"→ Найден родительский таск: ID={currentId}\n");
                }
                else if (parentAsgId.HasValue)
                {
                    currentId = parentAsgId.Value;
                    currentTable = "assignment";
                    Console.WriteLine($"→ Найдено родительское задание: ID={currentId}\n");
                }
            }

            // ШАГ 2: Рекурсивный поиск до корня
            while (iteration < maxIterations)
            {
                iteration++;
                Console.WriteLine($"[Итерация {iteration}] Текущий элемент: {currentTable} ID={currentId}");

                if (currentTable == "task")
                {
                    var (mainTaskId, parentTaskId, parentAsgId) = GetTaskRelations(currentId);

                    if (currentId == mainTaskId)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"\n✅ Найдена корневая задача! MainTask = {mainTaskId}");
                        Console.ResetColor();
                        return;
                    }

                    if (parentTaskId.HasValue)
                    {
                        currentId = parentTaskId.Value;
                        currentTable = "task";
                        Console.WriteLine($"→ Переход к родительскому таску: ID={currentId}");
                    }
                    else if (parentAsgId.HasValue)
                    {
                        currentId = parentAsgId.Value;
                        currentTable = "assignment";
                        Console.WriteLine($"→ Переход к родительскому заданию: ID={currentId}");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"\n❌ Ошибка: у задачи ID={currentId} отсутствуют связи (ParentTask и ParentAsg пустые)");
                        Console.ResetColor();
                        return;
                    }
                }
                else
                {
                    var (hasTaskLink, linkedTaskId) = CheckAssignmentSimple(currentId);

                    if (hasTaskLink && linkedTaskId.HasValue)
                    {
                        currentId = linkedTaskId.Value;
                        currentTable = "task";
                        Console.WriteLine($"→ Переход к связанной задаче: ID={currentId}");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"\n❌ Ошибка: у задания ID={currentId} отсутствует ссылка на задачу (поле task пустое)");
                        Console.ResetColor();
                        return;
                    }
                }

                Console.WriteLine();
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n❌ Достигнут лимит итераций ({maxIterations}). Возможна циклическая ссылка.");
            Console.ResetColor();
        }

        static (bool hasTask, long? taskId) CheckAssignment(long assignmentId, Guid discriminator)
        {
            using var cmd = new NpgsqlCommand(@"
                SELECT Id, task 
                FROM sungero_wf_assignment 
                WHERE Id = @id AND Discriminator = @discriminator", _dbConnection);

            cmd.Parameters.AddWithValue("id", NpgsqlTypes.NpgsqlDbType.Bigint, assignmentId);
            cmd.Parameters.AddWithValue("discriminator", NpgsqlTypes.NpgsqlDbType.Uuid, discriminator);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                var taskId = reader["task"] as long?;
                return (taskId.HasValue, taskId);
            }
            return (false, null);
        }

        static (bool hasParent, long? parentTaskId, long? parentAsgId) CheckTask(long taskId, Guid discriminator)
        {
            using var cmd = new NpgsqlCommand(@"
                SELECT Id, ParentTask, ParentAsg 
                FROM sungero_wf_task 
                WHERE Id = @id AND Discriminator = @discriminator", _dbConnection);

            cmd.Parameters.AddWithValue("id", NpgsqlTypes.NpgsqlDbType.Bigint, taskId);
            cmd.Parameters.AddWithValue("discriminator", NpgsqlTypes.NpgsqlDbType.Uuid, discriminator);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                var parentTask = reader["ParentTask"] as long?;
                var parentAsg = reader["ParentAsg"] as long?;
                return (parentTask.HasValue || parentAsg.HasValue, parentTask, parentAsg);
            }
            return (false, null, null);
        }

        static (long mainTaskId, long? parentTaskId, long? parentAsgId) GetTaskRelations(long taskId)
        {
            using var cmd = new NpgsqlCommand(@"
                SELECT Id, MainTask, ParentTask, ParentAsg 
                FROM sungero_wf_task 
                WHERE Id = @id", _dbConnection);

            cmd.Parameters.AddWithValue("id", NpgsqlTypes.NpgsqlDbType.Bigint, taskId);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                long mainTask = reader["MainTask"] is long mt ? mt : 0;
                long? parentTask = reader["ParentTask"] as long?;
                long? parentAsg = reader["ParentAsg"] as long?;
                return (mainTask, parentTask, parentAsg);
            }
            throw new Exception($"Задача с ID={taskId} не найдена");
        }

        static (bool hasTask, long? taskId) CheckAssignmentSimple(long assignmentId)
        {
            using var cmd = new NpgsqlCommand(@"
                SELECT Id, task 
                FROM sungero_wf_assignment 
                WHERE Id = @id", _dbConnection);

            cmd.Parameters.AddWithValue("id", NpgsqlTypes.NpgsqlDbType.Bigint, assignmentId);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                var taskId = reader["task"] as long?;
                return (taskId.HasValue, taskId);
            }
            return (false, null);
        }

        static void Cleanup()
        {
            if (_dbConnection?.State == ConnectionState.Open)
            {
                try
                {
                    _dbConnection.Close();
                    _dbConnection.Dispose();
                }
                catch { }
            }

            if (_sshPortForward?.IsStarted == true)
            {
                try
                {
                    _sshPortForward.Stop();
                }
                catch { }
            }

            if (_sshClient?.IsConnected == true)
            {
                try
                {
                    _sshClient.Disconnect();
                    _sshClient.Dispose();
                }
                catch { }
            }

            _dbConnection = null;
            _sshPortForward = null;
            _sshClient = null;
            _localTunnelPort = 0;
        }

        // ============ СИСТЕМА СОХРАНЕНИЯ СЕССИИ ============
        class ConnectionCredentials
        {
            public bool UseSsh { get; set; }
            public string SshHost { get; set; } = "";
            public int SshPort { get; set; }
            public string SshUser { get; set; } = "";
            public string SshPassword { get; set; } = "";
            public string DbHost { get; set; } = "";
            public int DbPort { get; set; }
            public string DbName { get; set; } = "";
            public string DbUser { get; set; } = "";
            public string DbPassword { get; set; } = "";
        }

        static void SaveCredentials(ConnectionCredentials creds)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(creds, options);
            byte[] plainData = Encoding.UTF8.GetBytes(json);
            byte[] encryptedData = ProtectedData.Protect(plainData, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(CredentialsFile, encryptedData);
        }

        static ConnectionCredentials LoadCredentials()
        {
            byte[] encryptedData = File.ReadAllBytes(CredentialsFile);
            byte[] plainData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            string json = Encoding.UTF8.GetString(plainData);
            return JsonSerializer.Deserialize<ConnectionCredentials>(json)
                ?? throw new Exception("Не удалось десериализовать учётные данные");
        }
    }
}