<?php
//V4.0
/**
 * Declarative CLI option parser built on top of getopt().
 * [RU] Декларативный парсер CLI-опций поверх getopt().
 *
 * Supports short and long options, value modes, defaults, validation
 * (required, unique, conflict groups), callbacks with execution order,
 * positional arguments, and built-in help generation with auto-width.
 * [RU] Поддерживает короткие и длинные опции, режимы значений, умолчания,
 * валидацию (обязательные, уникальные, группы конфликтов), колбэки с
 * порядком выполнения, позиционные аргументы и встроенную генерацию
 * help с авто-определением ширины терминала.
 *
 * Requires PHP 7.4+ (typed properties).
 * [RU] Требуется PHP 7.4+ (typed properties).
 *
 * @version 4.0.0
 */
class CliOptio
{
    /** Option is a flag, does not accept a value. [RU] Флаг, без значения. */
    public const VALUE_NONE = 0;
    /** Option accepts an optional value. [RU] Необязательное значение. */
    public const VALUE_OPTIONAL = 1;
    /** Option requires a value. [RU] Обязательное значение. */
    public const VALUE_REQUIRED = 2;

    protected array $ProcessedOptions;           // результат обработки (кэш)
    protected int $CounterOptId = 0;              // счётчик ID опций
    protected array $ShortOpts = [];              // короткие опции: имя => ID
    protected array $LongOpts = [];               // длинные опции: имя => ID
    protected array $IdOpts = [];                 // опции по ID: [ShortOpts, LongOpts]
    protected array $DescriptionOpts = [];        // описания опций для help
    protected array $ValueModeOpts = [];          // режимы значений (VALUE_*)
    protected array $DefaultValueOpts = [];       // значения по умолчанию
    protected array $ConflictGroups = [];         // группы конфликтов: имя => [ID]
    protected array $IsRequiredList = [];         // обязательные опции
    protected array $UniqueList = [];             // уникальные опции
    protected array $UseOnlyFirstValue = [];      // только первое значение
    protected array $CallbackOpts = [];           // колбэки опций
    protected array $CallbackOptsOrder = [];      // порядок колбэков
    protected string $ProgrammDescription = '';   // описание программы (help)
    protected string $HelpTextTop = '';           // текст над опциями (help)
    protected string $HelpTextBottom = '';        // текст под опциями (help)
    protected bool $UseOnlyFirstArg = false;      // только первый аргумент
    /** @var callable|null */ protected $CallbackArgs = null;  // колбэк позиционных аргументов
    protected bool $InternalHelp = false;         // встроенный help зарегистрирован
    protected int $ScreenWidth;                   // кэш ширины терминала
    protected int $ErrorExitCode = 0;             // код выхода при ошибке

    /**
     * Print formatted help topic to STDOUT.
     * [RU] Вывести отформатированную справку в STDOUT.
     *
     * Renders program description, top text, option list, and bottom text.
     * Auto-wraps text to terminal width.
     * [RU] Выводит описание программы, верхний текст, список опций и
     * нижний текст. Переносит текст по ширине терминала.
     */
    public function HelpTopic()
    {   
        $WidthScreen = $this->GetScreenWidth();
        global $argv;
        
        $this->PrintWithWordWrap($this->ProgrammDescription);
        $this->PrintWithWordWrap($this->HelpTextTop);
        $OptionIds = array_keys($this->DescriptionOpts);
        $diff = array_intersect($this->LongOpts, $OptionIds);
        $NoShortOption = false;
        $NoLongOption = false;
        if (count(array_intersect($this->ShortOpts, $OptionIds)) == 0)
        {
            $NoShortOption = true;
        }
        if (count($diff) == 0)
        {
            $NoLongOption = true;
            $MaxlenParamName = 0;
            
        }
        else
        {
            $MaxlenParamName = max(array_map('strlen', array_keys($diff))) + 2;     
        }

        $pregsize = $WidthScreen - $MaxlenParamName - (($NoShortOption)?0:4) - 6;
        if (!$NoShortOption || !$NoLongOption)
        {
            echo 'options:', PHP_EOL;
            foreach ($this->DescriptionOpts as $OptionId => $Description)
            {
                preg_match_all('/(.{0,'.$pregsize.'})(\ |$)/', $Description, $parts);

                if ($NoShortOption)
                {
                    $ShortOptionText = '';
                    $OptionDelimiter = '';              
                }
                else
                {
                    $ShortOptionText = ($this->IdOpts[$OptionId]['ShortOpts'] === null)? "  " : '-'.$this->IdOpts[$OptionId]['ShortOpts'];
                    $OptionDelimiter = ($this->IdOpts[$OptionId]['ShortOpts'] === null || $this->IdOpts[$OptionId]['LongOpts'] === null)? '  ' : ', ';
                }
                if ($NoLongOption)
                {
                    $LongOptionText = '';
                    $OptionDelimiter = '';
                }
                else
                {
                    $LongOptionText = (($this->IdOpts[$OptionId]['LongOpts'] === null)? str_repeat(' ', $MaxlenParamName):'--' . str_pad($this->IdOpts[$OptionId]['LongOpts'],$MaxlenParamName - 2));
                }
                $OptionText = "  " . $ShortOptionText . $OptionDelimiter . $LongOptionText . "    ";
                $FF = true;
                foreach ($parts[1] as $part)
                {
                    if ($part == '')
                    {
                        continue;
                    }
                    if ($FF)
                    {
                        echo $OptionText;
                        $FF = false;
                    }
                    else
                    {
                        echo str_repeat(' ', strlen($OptionText));
                    }
                    echo $part, PHP_EOL;
                }
            }
        }
        echo PHP_EOL;
        $this->PrintWithWordWrap($this->HelpTextBottom);

    }

    /**
     * Resolve option name (short or long) to its numeric ID.
     * [RU] Получить числовой ID опции по имени (короткому или длинному).
     *
     * @param string $option Option name without prefix ('v' or 'verbose').
     *                       [RU] Имя опции без префикса ('v' или 'verbose').
     * @return int|null Option ID or null if not found.
     *                  [RU] ID опции или null если не найдена.
     */
    protected function GetIdOption(string $option): ?int
    {
        if ($option == '')
        {
            return null;
        }
        
        if (isset($this->ShortOpts[$option]))
        {
            return $this->ShortOpts[$option];
        }
        if (isset($this->LongOpts[$option]))
        {
            return $this->LongOpts[$option];
        }
        
        return null;
    }

    /**
     * Declare a new CLI option.
     * [RU] Объявить новую CLI-опцию.
     *
     * At least one name (short or long) must be specified.
     * Short names must be a single character, long names at least 2 characters.
     * [RU] Необходимо указать хотя бы одно имя (короткое или длинное).
     * Короткое имя — один символ, длинное — минимум 2 символа.
     *
     * @param string|null $ShortOptionName Single character (e.g. 'v'), or null.
     *                                     [RU] Один символ (напр. 'v'), или null.
     * @param string|null $LongOptionName Multi-character name (e.g. 'verbose'), or null.
     *                                    [RU] Имя из нескольких символов (напр. 'verbose'), или null.
     *
     * @throws InvalidArgumentException If both names are null, names are invalid,
     *                                  or option already declared.
     *                                  [RU] Если оба имени null, имена невалидны
     *                                  или опция уже объявлена.
     */
    public function DeclareOption(?string $ShortOptionName, ?string $LongOptionName = null): void
    {
        if (is_null($ShortOptionName) && is_null($LongOptionName))
        {
            throw new \InvalidArgumentException('At least one option name (short or long) must be specified');
        }
        if (!is_null($ShortOptionName) && strlen($ShortOptionName) != 1)
        {
            throw new \InvalidArgumentException('Short option name must be a single character, got: ' . $ShortOptionName);
        }
        if (!is_null($LongOptionName) && strlen($LongOptionName) < 2)
        {
            throw new \InvalidArgumentException('Long option name must be at least 2 characters, got: ' . $LongOptionName);
        }
        if (isset($this->ShortOpts[$ShortOptionName]) || isset($this->LongOpts[$LongOptionName]))
        {
            throw new \InvalidArgumentException('Option already declared: ' . ($ShortOptionName ?? $LongOptionName));
        }
        if (!is_null($ShortOptionName))
        {
            $this->ShortOpts[$ShortOptionName] = $this->CounterOptId;
        }
        if (!is_null($LongOptionName))
        {
            $this->LongOpts[$LongOptionName] = $this->CounterOptId;
        }
        $this->IdOpts[$this->CounterOptId]['ShortOpts'] = $ShortOptionName;
        $this->IdOpts[$this->CounterOptId]['LongOpts'] = $LongOptionName;
        $this->CounterOptId++;
    }
    
    /**
     * Set the exit code used when validation fails.
     * [RU] Установить код выхода при ошибке валидации.
     *
     * Default is 0. Used when required parameter is missing, uniqueness
     * violated, or conflicting options are used together.
     * [RU] По умолчанию 0. Используется при отсутствии обязательного
     * параметра, нарушении уникальности или конфликте опций.
     *
     * @param int $code Exit code (e.g. 1 for error).
     *                  [RU] Код выхода (напр. 1 для ошибки).
     */
    public function SetErrorExitCode(int $code): void
    {
        $this->ErrorExitCode = $code;
    }
    
    /**
     * Set the program description shown at the top of help output.
     * [RU] Установить описание программы для вывода в начале справки.
     *
     * @param string $Description Description text (will be word-wrapped).
     *                            [RU] Текст описания (будет перенесён по словам).
     */
    public function SetProgrammDescription(string $Description): void
    {
        $this->ProgrammDescription = $Description;
    }
    
    /**
     * Set additional text shown above the options list in help.
     * [RU] Установить текст, выводимый над списком опций в справке.
     *
     * @param string $text Text to display (word-wrapped). Empty by default.
     *                    [RU] Отображаемый текст (с переносом). По умолчанию пустой.
     */
    public function SetHelpTextTop(string $text = ''): void
    {
        $this->HelpTextTop = $text;
    }
    
    /**
     * Set additional text shown below the options list in help.
     * [RU] Установить текст, выводимый под списком опций в справке.
     *
     * @param string $text Text to display (word-wrapped). Empty by default.
     *                    [RU] Отображаемый текст (с переносом). По умолчанию пустой.
     */
    public function SetHelpTextBottom(string $text = ''): void
    {
        $this->HelpTextBottom = $text;
    }
    
    /**
     * Set the description text for an option (used in help output).
     * [RU] Установить описание опции (используется в справке).
     *
     * @param string $Option Option name without prefix ('v' or 'verbose').
     *                        [RU] Имя опции без префикса ('v' или 'verbose').
     * @param string $Description Help text for this option.
     *                            [RU] Текст справки для этой опции.
     *
     * @throws InvalidArgumentException If the option has not been declared.
     *                                  [RU] Если опция не была объявлена.
     */
    public function SetOptionDescription(string $Option, string $Description): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        $this->DescriptionOpts[$IdOption] = $Description;
    }
    
    /**
     * Set how an option handles values.
     * [RU] Установить режим обработки значений опции.
     *
     * @param string $Option Option name without prefix.
     *                        [RU] Имя опции без префикса.
     * @param int $ValueMode One of CliOptio::VALUE_NONE (flag), CliOptio::VALUE_OPTIONAL (optional value),
     *                       or CliOptio::VALUE_REQUIRED (mandatory value). Default: CliOptio::VALUE_NONE.
     *                       [RU] Одно из: CliOptio::VALUE_NONE (флаг), CliOptio::VALUE_OPTIONAL
     *                       (необязательное значение) или CliOptio::VALUE_REQUIRED
     *                       (обязательное значение). По умолчанию: CliOptio::VALUE_NONE.
     *
     * @throws InvalidArgumentException If option not declared or value mode is invalid.
     *                                  [RU] Если опция не объявлена или режим невалиден.
     */
    public function SetOptionValueMode(string $Option, int $ValueMode = self::VALUE_NONE): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        if ($ValueMode < 0 || $ValueMode > 2)
        {
            throw new \InvalidArgumentException('Invalid value mode: ' . $ValueMode);
        }
        $this->ValueModeOpts[$IdOption] = $ValueMode;
    }

    /**
     * Set the default value for an option when not specified by the user.
     * [RU] Установить значение по умолчанию, если опция не указана пользователем.
     *
     * Behavior depends on value mode:
     * - CliOptio::VALUE_NONE: always stores false.
     * - CliOptio::VALUE_OPTIONAL: stores the given value.
     * - CliOptio::VALUE_REQUIRED: stores the given value (must not be null).
     * [RU] Поведение зависит от режима значения:
     * - CliOptio::VALUE_NONE: всегда сохраняет false.
     * - CliOptio::VALUE_OPTIONAL: сохраняет переданное значение.
     * - CliOptio::VALUE_REQUIRED: сохраняет переданное значение (не должно быть null).
     *
     * @param string $Option Option name without prefix.
     *                        [RU] Имя опции без префикса.
     * @param string|null $Value Default value. Null is treated as false.
     *                           [RU] Значение по умолчанию. Null интерпретируется как false.
     *
     * @throws InvalidArgumentException If option not declared, or REQUIRED mode with no value.
     *                                  [RU] Если опция не объявлена или REQUIRED без значения.
     */
    public function SetOptionDefaultValue(string $Option, ?string $Value = null): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        if (!isset($this->ValueModeOpts[$IdOption]))
        {
            $this->ValueModeOpts[$IdOption] = self::VALUE_NONE;
        }
        if (is_null($Value))
        {
            $Value = false;
        }
        switch ($this->ValueModeOpts[$IdOption])
        {
            case self::VALUE_NONE:
                $this->DefaultValueOpts[$IdOption] = false;
                break;
            case self::VALUE_OPTIONAL:
                $this->DefaultValueOpts[$IdOption] = $Value;
                break;
            case self::VALUE_REQUIRED:
                if ($Value !== false) 
                {
                    $this->DefaultValueOpts[$IdOption] = $Value;
                }
                else
                {
                    throw new \InvalidArgumentException('Default value is required for option: ' . $Option);
                }
                break;
        }
    }

    /**
     * Limit an option to its first value only (prevents array results).
     * [RU] Ограничить опцию первым значением (предотвращает массив).
     *
     * When enabled, if the option is specified multiple times, only the first
     * value is kept instead of returning an array.
     * [RU] Если включено и опция указана несколько раз, сохраняется только
     * первое значение вместо массива.
     *
     * @param string $Option Option name without prefix.
     *                        [RU] Имя опции без префикса.
     * @param bool $val True to enable (default), false to disable.
     *                  [RU] True для включения (по умолчанию), false для отключения.
     *
     * @throws InvalidArgumentException If option not declared.
     *                                  [RU] Если опция не объявлена.
     */
    public function SetOptionUseOnlyFirstValue(string $Option, bool $val = true): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        $this->UseOnlyFirstValue[$IdOption] = $val;
    }
    
    /**
     * Add an option to a conflict group. Options in the same group cannot be used together.
     * [RU] Добавить опцию в группу конфликта. Опции в одной группе нельзя использовать вместе.
     *
     * Example: SetOptionConflictGroup('v', 'verbosity') and SetOptionConflictGroup('q', 'verbosity')
     * will prevent -v and -q from being used together.
     * [RU] Пример: SetOptionConflictGroup('v', 'verbosity') и
     * SetOptionConflictGroup('q', 'verbosity') запретит совместное использование -v и -q.
     *
     * @param string $Option Option name without prefix.
     *                        [RU] Имя опции без префикса.
     * @param string $ConflictGroup Group identifier (non-empty string).
     *                              [RU] Идентификатор группы (непустая строка).
     *
     * @throws InvalidArgumentException If option not declared or group name is empty.
     *                                  [RU] Если опция не объявлена или имя группы пустое.
     */
    public function SetOptionConflictGroup(string $Option, string $ConflictGroup): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        if ($ConflictGroup == '')
        {
            throw new \InvalidArgumentException('Conflict group name must not be empty');
        }
        $this->ConflictGroups[$ConflictGroup][] = $IdOption;
    }

    /**
     * Mark an option as required. Processing will fail if the option is missing.
     * [RU] Пометить опцию как обязательную. Обработка завершится ошибкой если опция отсутствует.
     *
     * @param string $Option Option name without prefix.
     *                        [RU] Имя опции без префикса.
     *
     * @throws InvalidArgumentException If option not declared.
     *                                  [RU] Если опция не объявлена.
     */
    public function SetOptionIsRequired(string $Option): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        $this->IsRequiredList[] = $IdOption;
    }

    /**
     * Mark an option as unique (must not be specified more than once).
     * [RU] Пометить опцию как уникальную (не должна указываться более одного раза).
     *
     * @param string $Option Option name without prefix.
     *                        [RU] Имя опции без префикса.
     *
     * @throws InvalidArgumentException If option not declared.
     *                                  [RU] Если опция не объявлена.
     */
    public function SetOptionUnique(string $Option): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        $this->UniqueList[] = $IdOption;
    }

    /**
     * Set a callback handler for an option. Called after validation, before RunProcessing returns.
     * [RU] Установить обработчик-колбэк для опции. Вызывается после валидации, до возврата RunProcessing.
     *
     * Callback signature: function(mixed $values, array $allOptions): void
     * [RU] Сигнатура колбэка: function(mixed $values, array $allOptions): void
     *
     * @param string $Option Option name without prefix.
     *                        [RU] Имя опции без префикса.
     * @param callable|null $CallbackHandler Callback function. Null to remove.
     *                                      [RU] Функция-обработчик. Null для удаления.
     * @param int $Order Execution order (lower = earlier). Default 255.
     *                   [RU] Порядок выполнения (меньше = раньше). По умолчанию 255.
     *
     * @throws InvalidArgumentException If option not declared.
     *                                  [RU] Если опция не объявлена.
     */
    public function SetOptionCallbackHandler(string $Option, callable $CallbackHandler = null, int $Order = 255): void
    {
        $IdOption = $this->GetIdOption($Option);
        if (is_null($IdOption))
        {
            throw new \InvalidArgumentException('Unknown option: ' . $Option);
        }
        $this->CallbackOpts[$IdOption] = $CallbackHandler;
        $this->CallbackOptsOrder[$IdOption] = $Order;
    }
    
    /**
     * Register a built-in help option (-h and optionally --help).
     * [RU] Зарегистрировать встроенную опцию help (-h и опционально --help).
     *
     * When -h or --help is used, prints help and exits.
     * Can only be called once; subsequent calls are ignored.
     * [RU] При использовании -h или --help выводит справку и завершает работу.
     * Можно вызвать только один раз; последующие вызовы игнорируются.
     *
     * @param bool $OnlyShort If true, only -h is registered (no --help). Default false.
     *                        [RU] Если true, регистрируется только -h (без --help). По умолчанию false.
     */
    public function UseInternalHelp(bool $OnlyShort = false): void
    {
        if (!$this->InternalHelp)
        {
            
            $long = ($OnlyShort)? null: 'help';
            $this->InternalHelp = true;
            $this->DeclareOption('h', $long);
            $this->SetOptionDescription('h', 'show this help topic and quit');
            $this->SetOptionCallbackHandler('h', [$this, 'HelpTopic']);
            $this->SetOptionUseOnlyFirstValue('h');
        }
    }
    
    /**
     * Parse CLI arguments and run all validations and callbacks.
     * [RU] Разобрать CLI-аргументы, выполнить валидацию и колбэки.
     *
     * On first call: parses $argv via getopt(), applies defaults, validates
     * required/unique/conflict constraints, executes callbacks, and returns
     * the result array. Subsequent calls return the cached result.
     * [RU] При первом вызове: разбирает $argv через getopt(), применяет
     * умолчания, проверяет обязательные/уникальные/конфликтующие ограничения,
     * выполняет колбэки и возвращает массив результата.
     * Последующие вызовы возвращают кэшированный результат.
     *
     * Result array keys: option names (without prefix), '!ARGS' for positional arguments.
     * [RU] Ключи массива результата: имена опций (без префикса), '!ARGS' для позиционных аргументов.
     *
     * On validation failure: writes error to STDERR and calls exit().
     * [RU] При ошибке валидации: выводит ошибку в STDERR и вызывает exit().
     *
     * @return array<string,mixed> Parsed options and arguments.
     *                                [RU] Разобранные опции и аргументы.
     */
    public function RunProcessing(): array
    {
        if (isset($this->ProcessedOptions))
        {
            return $this->ProcessedOptions;
        }
        global $argc, $argv;
        //формирование доступных опций
        $ShortOptsList = '';
        foreach ($this->ShortOpts as $Option => $IdOption)
        {
            $ShortOptsList .= $Option;
            if (isset($this->ValueModeOpts[$IdOption]))
            {
                switch ($this->ValueModeOpts[$IdOption])
                {
                    case self::VALUE_NONE:
                        break;
                    case self::VALUE_OPTIONAL:
                        $ShortOptsList .= '::';
                        break;
                    case self::VALUE_REQUIRED:
                        $ShortOptsList .= ':';
                        break;
                }
                
            }
        }
        $LongOptsList = [];
        foreach ($this->LongOpts as $Option => $IdOption)
        {
            if (isset($this->ValueModeOpts[$IdOption]))
            {
                switch ($this->ValueModeOpts[$IdOption])
                {
                    case self::VALUE_NONE:
                        break;
                    case self::VALUE_OPTIONAL:
                        $Option .= '::';
                        break;
                    case self::VALUE_REQUIRED:
                        $Option .= ':';
                        break;
                }
            }
            $LongOptsList[] = $Option;
        }
        unset($Option, $IdOption);
        
        //базовый парсинг
        $ParsedOptions = getopt($ShortOptsList, $LongOptsList,$index);
        //приведение разноимённых опций но под одним ID к сокращенной опции с объединением значений 
        foreach ($this->IdOpts as $IdOption => $Options)
        {
            if (!is_null($Options['ShortOpts']) && !is_null($Options['LongOpts']))
            {
                if (isset($ParsedOptions[$Options['ShortOpts']]) && isset($ParsedOptions[$Options['LongOpts']]))
                {
                    if (!is_array($ParsedOptions[$Options['ShortOpts']]))
                    {
                        $TempShortValue = $ParsedOptions[$Options['ShortOpts']];
                        $ParsedOptions[$Options['ShortOpts']] = [];
                        $ParsedOptions[$Options['ShortOpts']][] = $TempShortValue;
                    }
                    
                    if (!is_array($ParsedOptions[$Options['LongOpts']]))
                    {
                        $TempLongValue = $ParsedOptions[$Options['LongOpts']];
                        $ParsedOptions[$Options['LongOpts']] = [];
                        $ParsedOptions[$Options['LongOpts']][] = $TempLongValue;
                    }
                    $ParsedOptions[$Options['ShortOpts']] = array_merge($ParsedOptions[$Options['ShortOpts']], $ParsedOptions[$Options['LongOpts']]);
                    unset($ParsedOptions[$Options['LongOpts']]);
                }
            }
        }
        //докидывание опций, которые не были указаны но объявлены как имеющие значение по умолчанию
        foreach ($this->DefaultValueOpts as $IdOption => $Value)
        {
            if (!isset($ParsedOptions[$this->IdOpts[$IdOption]['ShortOpts']]) && !isset($ParsedOptions[$this->IdOpts[$IdOption]['LongOpts']]))
            {
                if (!is_null($this->IdOpts[$IdOption]['ShortOpts']))
                {
                    $ParsedOptions[$this->IdOpts[$IdOption]['ShortOpts']] = $Value;
                }
                elseif (!is_null($this->IdOpts[$IdOption]['LongOpts']))
                {
                    $ParsedOptions[$this->IdOpts[$IdOption]['LongOpts']] = $Value;          
                }
            }
        }
        
        //докидывание аргументов, как отдельной опции
        for ($i = $index; $i < $argc; $i++)
        {
            $ParsedOptions['!ARGS'][] = $argv[$i];
        }
        if ($this->UseOnlyFirstArg && isset($ParsedOptions['!ARGS']))
        {
            $ParsedOptions['!ARGS'] = $ParsedOptions['!ARGS'][0];
        }
        
        //обработка опции "использовать только одно значение" гарантирует что значение опции будет использовано первое найденное и не будет массивом значений
        foreach ($ParsedOptions as $Option => $Values)
        {
            $IdOption = $this->GetIdOption($Option);
            if (isset($this->UseOnlyFirstValue[$IdOption]) && is_array($Values))
            {
                if ($this->UseOnlyFirstValue[$IdOption])
                {
                    $ParsedOptions[$Option] = $Values[0];
                }
            }
        }

        // проверка на пропущенность обязательных параметров
        foreach ($this->IsRequiredList as $IdOption)
        {
            if (!isset($ParsedOptions[$this->IdOpts[$IdOption]['ShortOpts']]) && !isset($ParsedOptions[$this->IdOpts[$IdOption]['LongOpts']]))
            {
                $OptName = $this->IdOpts[$IdOption]['ShortOpts'] ?? $this->IdOpts[$IdOption]['LongOpts'];
                fwrite(STDERR, "Required parameter " . (((strlen($OptName) == 1) ? "-" : "--") . $OptName) . " is missing!" . PHP_EOL);
                exit($this->ErrorExitCode);
            }
        }
        
        //проверка на всякие ограничения
        //проверка на запрещенность нескольких значений для опции
        foreach ($ParsedOptions as $Option => $Values)
        {
            $IdOption = $this->GetIdOption($Option);
            if (array_search($IdOption, $this->UniqueList) !== false && is_array($Values))
            {
                $OptPrintname = ((strlen($Option) == 1)? '-' : '--').$Option;
                fwrite(STDERR, "Parameter {$OptPrintname} must be unique!".PHP_EOL);
                exit($this->ErrorExitCode);
            }
        }
        //проверка на конфликты опций
        $ParsedOptList = array_keys($ParsedOptions);    
        $ParsedIdOptionList = [];
        foreach ($ParsedOptList as $Option)
        {
            $ParsedIdOptionList [] = $this->GetIdOption($Option);
        }
        foreach ($this->ConflictGroups as $ConflictGroupOpts)
        {
            $CollList = array_intersect($ConflictGroupOpts, $ParsedIdOptionList);
            if (count($CollList) > 1)
            {
                $OptPrintname = array_merge(array_keys(array_intersect($this->ShortOpts, $CollList)),array_keys(array_intersect($this->LongOpts, $CollList)));
                sort($OptPrintname);
                foreach ($OptPrintname as &$Value)
                {
                    $Value = ((strlen($Value) == 1)? '-' : '--').$Value;
                }
                fwrite(STDERR, "Options " . implode(', ', $OptPrintname) . " can not be used together.".PHP_EOL);
                exit($this->ErrorExitCode);
            }
        }
        //проверяем используется и вызывается ли встроенный help
        if ($this->InternalHelp &&(isset($ParsedOptions['h']) || isset($ParsedOptions['help'])))
        {
            $this->HelpTopic();
            exit();         
        }
        // в этом месте надо перебрать опции и вызвать обработчики
        $CBC = [];
        foreach ($ParsedOptions as $OptName => $Values)
        {
            $IdOption = $this->GetIdOption($OptName);
            if (isset($this->CallbackOpts[$IdOption]))
            {
                if (is_callable($this->CallbackOpts[$IdOption], true))
                {
                    $CBC[$this->CallbackOptsOrder[$IdOption]][$IdOption] = $Values;
                }
            }
        }
        ksort($CBC);
        foreach ($CBC as $IdOptions)
        {
            foreach ($IdOptions as $IdOption => $Values)
            {
                call_user_func($this->CallbackOpts[$IdOption], $Values, $ParsedOptions);
            }
        }
        unset($CBC);
        
        //проверяем есть ли обработчик для аргументов и если есть, то выполняем
        if (isset($this->CallbackArgs))
        {
            if (is_callable($this->CallbackArgs, true))
            {
                $ARGS = (isset($ParsedOptions['!ARGS']))? $ParsedOptions['!ARGS']: null;
                call_user_func($this->CallbackArgs, $ARGS, $ParsedOptions);
            }
        }
        //сохраняем обработанные опции
        $this->ProcessedOptions = $ParsedOptions;
        return $this->ProcessedOptions;
    }

    /**
     * Set a callback handler for positional arguments.
     * [RU] Установить обработчик-колбэк для позиционных аргументов.
     *
     * Callback signature: function(?array $args, array $allOptions): void
     * [RU] Сигнатура колбэка: function(?array $args, array $allOptions): void
     *
     * @param callable|null $CallbackHandler Callback function. Null to remove.
     *                                      [RU] Функция-обработчик. Null для удаления.
     */
    public function SetArgsCallbackHandler(callable $CallbackHandler = null): void
    {
        $this->CallbackArgs = $CallbackHandler;
    }
    
    /**
     * Keep only the first positional argument (instead of an array).
     * [RU] Сохранить только первый позиционный аргумент (вместо массива).
     *
     * @param bool $val True to enable (default), false to disable.
     *                  [RU] True для включения (по умолчанию), false для отключения.
     */
    public function SetArgsUseOnlyFirstArg(bool $val = true): void
    {
        $this->UseOnlyFirstArg = $val;
    }
    
    /**
     * Print text to STDOUT with word-wrapping at terminal width.
     * [RU] Вывести текст в STDOUT с переносом по ширине терминала.
     *
     * @param string $text Text to print (empty text is silently skipped).
     *                     [RU] Текст для вывода (пустой текст пропускается).
     */
    protected function PrintWithWordWrap(string $text): void
    {
        
        if($text == '')
        {
            return;
        }
        $pregsize = $this->GetScreenWidth() - 2;
        preg_match_all('/(.{0,'.$pregsize.'})(\ |$)/', $text, $parts);
        foreach ($parts[1] as $part)
        {
            if ($part == '')
            {
                continue;
            }
            echo $part, PHP_EOL;
        }       
    }
    
    /**
     * Check whether STDOUT is connected to a terminal.
     * [RU] Проверить подключён ли STDOUT к терминалу.
     *
     * Uses stream_isatty (PHP 8.2+) with fallback to posix_isatty (ext-posix).
     * Returns false if neither function is available.
     * [RU] Использует stream_isatty (PHP 8.2+) с fallback на posix_isatty (ext-posix).
     * Возвращает false если ни одна функция недоступна.
     *
     * @return bool True if STDOUT is a TTY, false otherwise.
     *              [RU] True если STDOUT подключён к терминалу, иначе false.
     */
    protected function IsTty(): bool
    {
        if (function_exists('stream_isatty'))
        {
            return stream_isatty(STDOUT);
        }
        if (function_exists('posix_isatty'))
        {
            return posix_isatty(STDOUT);
        }
        return false;
    }

    /**
     * Detect and cache terminal width.
     * [RU] Определить и закэшировать ширину терминала.
     *
     * Returns 80 when not connected to a TTY (pipe, cron, subprocess, etc.).
     * Result is cached after first call.
     * [RU] Возвращает 80 когда не подключён к терминалу (pipe, cron,
     * subprocess и т.д.). Результат кэшируется после первого вызова.
     *
     * @return int Terminal width in columns.
     *              [RU] Ширина терминала в колонках.
     */
    protected function GetScreenWidth(): int
    {
        if (!isset($this->ScreenWidth))
        {
            $this->ScreenWidth = 80;
            if ($this->IsTty())
            {
                $stty = shell_exec('stty -a');
                if (is_string($stty))
                {
                    $stty = array_map('trim', explode(';', $stty));
                    foreach ($stty as $value)
                    {
                        if (strtok($value, ' =') == 'columns')
                        {
                            $this->ScreenWidth = (int) strtok(' =');
                            break;
                        }
                    }
                }
            }
        }
        return $this->ScreenWidth;
    }
}
