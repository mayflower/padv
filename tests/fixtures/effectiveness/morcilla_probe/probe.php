<?php
/*
 * Minimal interception target for the morcilla response-header contract test.
 *
 * Probe::query is a userland method, so it is observable regardless of PHP's
 * opcode specialisation (which is why e.g. strlen is not interceptable).
 */

class Probe
{
    public function query($queryString)
    {
        return strlen($queryString);
    }
}

$value = $_GET['q'] ?? 'default-value';
$repeat = (int)($_GET['repeat'] ?? 1);

$probe = new Probe();
for ($i = 0; $i < $repeat; $i++) {
    $probe->query("SELECT * FROM accounts WHERE username='" . $value . "'");
}

echo "probe-ok\n";
