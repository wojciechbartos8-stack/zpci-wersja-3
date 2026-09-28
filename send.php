<?php

/*
|--------------------------------------------------------------------------
| ZPCI - SEND.PHP
|--------------------------------------------------------------------------
| Obsługa formularza CS – Centrum Zgłoszeń
|
| GET:
|   send.php?csrf=json
|   -> zwraca token CSRF w JSON
|
| POST:
|   -> sprawdza formularz
|   -> wysyła wiadomość
|   -> przekierowuje z powrotem do cs.html
|--------------------------------------------------------------------------
*/

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| SESJA
|--------------------------------------------------------------------------
*/

$httpsEnabled =
    isset($_SERVER['HTTPS'])
    && $_SERVER['HTTPS'] !== ''
    && $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params([
    'httponly' => true,
    'secure'   => $httpsEnabled,
    'samesite' => 'Lax',
]);

session_start();


/*
|--------------------------------------------------------------------------
| NAGŁÓWKI BEZPIECZEŃSTWA
|--------------------------------------------------------------------------
*/

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');


/*
|--------------------------------------------------------------------------
| KONFIGURACJA
|--------------------------------------------------------------------------
*/

const CSRF_SESSION_KEY = 'zpci_csrf_token';

const FORM_RATE_LIMIT_SECONDS = 30;

const MIN_FORM_TIME_SECONDS = 2;
const MAX_FORM_TIME_SECONDS = 7200;

const MAX_NAME_LENGTH = 60;
const MAX_SURNAME_LENGTH = 80;
const MAX_EMAIL_LENGTH = 160;
const MAX_PHONE_LENGTH = 30;
const MAX_COMPANY_LENGTH = 150;
const MAX_MESSAGE_LENGTH = 3000;

const RECIPIENT_EMAIL = 'biuro@zpci.pl';


/*
|--------------------------------------------------------------------------
| SZKOLENIA
|--------------------------------------------------------------------------
*/

const TRAININGS = [
    'Akademia Młodego Informatyka',
    'Analiza danych',
    'MS Access',
    'SQL / PL/SQL',
    'Płatnik',
    'Symfonia Faktura',
    'MS Office – poziom 1',
    'MS Office – poziom 2',
    'Microsoft Excel',
    'MS Office Professional',
    'MS Project',
    'Profesjonalne prezentacje PowerPoint',
    'VBA – Visual Basic for Applications',
    'C++',
    'C#',
    'Java',
    'JavaScript – programowanie dynamicznych stron',
    'PHP i MySQL – programowanie stron',
    'CAD – poziom 1',
    'CAD – poziom 2',
    'CorelDRAW',
    'GIMP',
    'Photoshop'
];


/*
|--------------------------------------------------------------------------
| USŁUGI
|--------------------------------------------------------------------------
*/

const SERVICES = [
    'Naprawa i serwis komputerów',
    'Doradztwo informatyczne',
    'Projektowanie i edycja stron internetowych',
    'Projektowanie rozwiązań informatycznych',
    'Marketing IT',
    'Projektowanie strategii kampanii marketingowych w Internecie',
    'Selekcja kandydatów IT',
    'Inne usługi IT'
];


/*
|--------------------------------------------------------------------------
| FUNKCJE
|--------------------------------------------------------------------------
*/


function redirectToForm(string $status): never
{
    header(
        'Location: cs.html?status=' . rawurlencode($status),
        true,
        303
    );

    exit;
}


/*
|--------------------------------------------------------------------------
| TOKEN CSRF
|--------------------------------------------------------------------------
*/

function getCsrfToken(): string
{
    if (
        !isset($_SESSION[CSRF_SESSION_KEY])
        || !is_string($_SESSION[CSRF_SESSION_KEY])
        || strlen($_SESSION[CSRF_SESSION_KEY]) !== 64
        || !ctype_xdigit($_SESSION[CSRF_SESSION_KEY])
    ) {
        $_SESSION[CSRF_SESSION_KEY] = bin2hex(
            random_bytes(32)
        );
    }

    return $_SESSION[CSRF_SESSION_KEY];
}


/*
|--------------------------------------------------------------------------
| CZYSZCZENIE TEKSTU
|--------------------------------------------------------------------------
*/

function cleanText(mixed $value, int $maxLength): string
{
    $value = trim((string) $value);

    $cleaned = preg_replace(
        '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
        '',
        $value
    );

    if ($cleaned === null) {
        $cleaned = '';
    }

    if (function_exists('mb_substr')) {
        return mb_substr(
            $cleaned,
            0,
            $maxLength,
            'UTF-8'
        );
    }

    return substr(
        $cleaned,
        0,
        $maxLength
    );
}


/*
|--------------------------------------------------------------------------
| POBRANIE STRINGA Z POST
|--------------------------------------------------------------------------
*/

function postString(string $key): string
{
    if (!isset($_POST[$key])) {
        return '';
    }

    if (!is_string($_POST[$key])) {
        return '';
    }

    return $_POST[$key];
}


/*
|--------------------------------------------------------------------------
| IP
|--------------------------------------------------------------------------
*/

function getClientIp(): string
{
    if (
        isset($_SERVER['REMOTE_ADDR'])
        && is_string($_SERVER['REMOTE_ADDR'])
        && $_SERVER['REMOTE_ADDR'] !== ''
    ) {
        return $_SERVER['REMOTE_ADDR'];
    }

    return 'unknown';
}


/*
|--------------------------------------------------------------------------
| GET: TOKEN CSRF W JSON
|--------------------------------------------------------------------------
|
| cs.html wykonuje:
|
| fetch('send.php?csrf=json', ...)
|
|--------------------------------------------------------------------------
*/

if (
    $_SERVER['REQUEST_METHOD'] === 'GET'
    && isset($_GET['csrf'])
    && $_GET['csrf'] === 'json'
) {

    header(
        'Content-Type: application/json; charset=UTF-8'
    );

    try {

        $token = getCsrfToken();

        /*
        |--------------------------------------------------------------
        | Bardzo ważne:
        | wymuszamy zapis sesji zanim odpowiemy JSON-em.
        |--------------------------------------------------------------
        */

        session_write_close();

        echo json_encode(
            [
                'success'    => true,
                'csrf_token' => $token
            ],
            JSON_UNESCAPED_UNICODE
            | JSON_UNESCAPED_SLASHES
            | JSON_THROW_ON_ERROR
        );

    } catch (Throwable $exception) {

        http_response_code(500);

        /*
        |--------------------------------------------------------------
        | Próba zapisania sesji, jeżeli nadal jest otwarta.
        |--------------------------------------------------------------
        */

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        echo json_encode(
            [
                'success' => false,
                'error'   => 'Nie udało się przygotować zabezpieczenia formularza.'
            ],
            JSON_UNESCAPED_UNICODE
            | JSON_UNESCAPED_SLASHES
        );
    }

    exit;
}


/*
|--------------------------------------------------------------------------
| TYLKO POST
|--------------------------------------------------------------------------
*/

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirectToForm('invalid');
}


/*
|--------------------------------------------------------------------------
| LIMIT ROZMIARU ŻĄDANIA
|--------------------------------------------------------------------------
*/

if (
    isset($_SERVER['CONTENT_LENGTH'])
    && is_numeric($_SERVER['CONTENT_LENGTH'])
) {

    if ((int) $_SERVER['CONTENT_LENGTH'] > 100000) {
        redirectToForm('security');
    }
}


/*
|--------------------------------------------------------------------------
| SPRAWDZENIE CSRF
|--------------------------------------------------------------------------
*/

$sessionToken = '';

if (
    isset($_SESSION[CSRF_SESSION_KEY])
    && is_string($_SESSION[CSRF_SESSION_KEY])
) {
    $sessionToken = $_SESSION[CSRF_SESSION_KEY];
}

$formToken = postString('csrf_token');


if (
    $sessionToken === ''
    || strlen($sessionToken) !== 64
    || !ctype_xdigit($sessionToken)
    || $formToken === ''
    || strlen($formToken) !== 64
    || !ctype_xdigit($formToken)
    || !hash_equals(
        $sessionToken,
        $formToken
    )
) {
    redirectToForm('security');
}


/*
|--------------------------------------------------------------------------
| TOKEN JEDNORAZOWY
|--------------------------------------------------------------------------
*/

unset($_SESSION[CSRF_SESSION_KEY]);


/*
|--------------------------------------------------------------------------
| HONEYPOT
|--------------------------------------------------------------------------
*/

$website = postString('website');
$companyUrl = postString('company_url');

if (
    trim($website) !== ''
    || trim($companyUrl) !== ''
) {
    redirectToForm('security');
}


/*
|--------------------------------------------------------------------------
| CZAS ZAŁADOWANIA FORMULARZA
|--------------------------------------------------------------------------
*/

$formLoaded = postString('form_loaded');


if (
    $formLoaded === ''
    || !ctype_digit($formLoaded)
) {
    redirectToForm('security');
}


$formLoadedTimestamp = (int) $formLoaded;
$currentTimestamp = time();

$elapsed = $currentTimestamp - $formLoadedTimestamp;


if (
    $elapsed < MIN_FORM_TIME_SECONDS
    || $elapsed > MAX_FORM_TIME_SECONDS
) {
    redirectToForm('security');
}


/*
|--------------------------------------------------------------------------
| RATE LIMIT
|--------------------------------------------------------------------------
*/

if (
    isset($_SESSION['zpci_last_submit'])
    && is_numeric($_SESSION['zpci_last_submit'])
) {

    $lastSubmit = (int) $_SESSION['zpci_last_submit'];

    if (
        ($currentTimestamp - $lastSubmit)
        < FORM_RATE_LIMIT_SECONDS
    ) {
        redirectToForm('rate');
    }
}


/*
|--------------------------------------------------------------------------
| POBRANIE DANYCH
|--------------------------------------------------------------------------
*/

$rodzajZgloszenia = cleanText(
    postString('rodzaj_zgloszenia'),
    30
);

$imie = cleanText(
    postString('imie'),
    MAX_NAME_LENGTH
);

$nazwisko = cleanText(
    postString('nazwisko'),
    MAX_SURNAME_LENGTH
);

$email = trim(
    postString('email')
);

$telefon = cleanText(
    postString('telefon'),
    MAX_PHONE_LENGTH
);

$firma = cleanText(
    postString('firma'),
    MAX_COMPANY_LENGTH
);

$szkolenie = cleanText(
    postString('szkolenie'),
    200
);

$usluga = cleanText(
    postString('usluga'),
    200
);

$wiadomosc = cleanText(
    postString('wiadomosc'),
    MAX_MESSAGE_LENGTH
);

$zgoda = postString('zgoda');


/*
|--------------------------------------------------------------------------
| RODZAJ ZGŁOSZENIA
|--------------------------------------------------------------------------
*/

if (
    $rodzajZgloszenia !== 'szkolenie'
    && $rodzajZgloszenia !== 'usluga'
) {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| IMIĘ
|--------------------------------------------------------------------------
*/

$nameLength = function_exists('mb_strlen')
    ? mb_strlen($imie, 'UTF-8')
    : strlen($imie);


if (
    $nameLength < 2
    || $nameLength > MAX_NAME_LENGTH
) {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| NAZWISKO
|--------------------------------------------------------------------------
*/

$surnameLength = function_exists('mb_strlen')
    ? mb_strlen($nazwisko, 'UTF-8')
    : strlen($nazwisko);


if (
    $surnameLength < 2
    || $surnameLength > MAX_SURNAME_LENGTH
) {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| E-MAIL
|--------------------------------------------------------------------------
*/

if (
    $email === ''
    || strlen($email) > MAX_EMAIL_LENGTH
    || !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| OCHRONA NAGŁÓWKA E-MAIL
|--------------------------------------------------------------------------
*/

if (preg_match('/[\r\n]/', $email)) {
    redirectToForm('security');
}


/*
|--------------------------------------------------------------------------
| TELEFON
|--------------------------------------------------------------------------
*/

if (strlen($telefon) > MAX_PHONE_LENGTH) {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| FIRMA
|--------------------------------------------------------------------------
*/

if (strlen($firma) > MAX_COMPANY_LENGTH) {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| WIADOMOŚĆ
|--------------------------------------------------------------------------
*/

if (strlen($wiadomosc) > MAX_MESSAGE_LENGTH) {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| ZGODA
|--------------------------------------------------------------------------
*/

if ($zgoda !== '1') {
    redirectToForm('validation');
}


/*
|--------------------------------------------------------------------------
| SZKOLENIE / USŁUGA
|--------------------------------------------------------------------------
*/

if ($rodzajZgloszenia === 'szkolenie') {

    if (
        $szkolenie === ''
        || !in_array(
            $szkolenie,
            TRAININGS,
            true
        )
    ) {
        redirectToForm('validation');
    }

    $wybranaPozycja = $szkolenie;

} else {

    if (
        $usluga === ''
        || !in_array(
            $usluga,
            SERVICES,
            true
        )
    ) {
        redirectToForm('validation');
    }

    $wybranaPozycja = $usluga;
}


/*
|--------------------------------------------------------------------------
| INFORMACJE TECHNICZNE
|--------------------------------------------------------------------------
*/

$ipAddress = getClientIp();

$userAgent = isset($_SERVER['HTTP_USER_AGENT'])
    ? cleanText(
        $_SERVER['HTTP_USER_AGENT'],
        500
    )
    : 'brak';


/*
|--------------------------------------------------------------------------
| TREŚĆ WIADOMOŚCI
|--------------------------------------------------------------------------
*/

$messageParts = [];

$messageParts[] = 'ZPCI – Centrum Zgłoszeń';
$messageParts[] = '========================================';
$messageParts[] = '';

$messageParts[] = 'RODZAJ ZGŁOSZENIA';

if ($rodzajZgloszenia === 'szkolenie') {
    $messageParts[] = 'Szkolenie';
} else {
    $messageParts[] = 'Usługa IT';
}

$messageParts[] = '';

$messageParts[] = 'WYBRANA POZYCJA';
$messageParts[] = $wybranaPozycja;

$messageParts[] = '';

$messageParts[] = 'DANE ZGŁASZAJĄCEGO';
$messageParts[] = '----------------------------------------';

$messageParts[] = 'Imię: ' . $imie;
$messageParts[] = 'Nazwisko: ' . $nazwisko;
$messageParts[] = 'E-mail: ' . $email;

if ($telefon !== '') {
    $messageParts[] = 'Telefon: ' . $telefon;
}

if ($firma !== '') {
    $messageParts[] = 'Firma: ' . $firma;
}

$messageParts[] = '';

$messageParts[] = 'WIADOMOŚĆ';
$messageParts[] = '----------------------------------------';

if ($wiadomosc !== '') {
    $messageParts[] = $wiadomosc;
} else {
    $messageParts[] = '(brak dodatkowej wiadomości)';
}

$messageParts[] = '';

$messageParts[] = 'INFORMACJE TECHNICZNE';
$messageParts[] = '----------------------------------------';

$messageParts[] = 'Adres IP: ' . $ipAddress;
$messageParts[] = 'User-Agent: ' . $userAgent;
$messageParts[] = 'Czas wysłania: ' . date('Y-m-d H:i:s');


$message = implode(
    PHP_EOL,
    $messageParts
);


/*
|--------------------------------------------------------------------------
| TEMAT I NAGŁÓWKI
|--------------------------------------------------------------------------
*/

$subject = 'ZPCI – nowe zgłoszenie z formularza CS';

$headers = [];

$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-Type: text/plain; charset=UTF-8';
$headers[] = 'From: ZPCI <biuro@zpci.pl>';
$headers[] = 'Reply-To: ' . $email;


/*
|--------------------------------------------------------------------------
| WYSŁANIE WIADOMOŚCI
|--------------------------------------------------------------------------
*/

$mailSent = false;

try {

    $mailSent = mail(
        RECIPIENT_EMAIL,
        $subject,
        $message,
        implode(
            "\r\n",
            $headers
        )
    );

} catch (Throwable $exception) {

    $mailSent = false;
}


/*
|--------------------------------------------------------------------------
| ZAPIS OSTATNIEGO WYSŁANIA
|--------------------------------------------------------------------------
*/

$_SESSION['zpci_last_submit'] = time();


/*
|--------------------------------------------------------------------------
| POWRÓT DO CS.HTML
|--------------------------------------------------------------------------
*/

if ($mailSent === true) {
    redirectToForm('success');
}

redirectToForm('mail_error');
?>
