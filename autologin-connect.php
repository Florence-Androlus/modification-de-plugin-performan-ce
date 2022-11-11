<?php
/**
 * This is a simple working ReducCE (SKI LOISIRS DIFFUSION) autologin connector, for test purpose only.
 * It is recommended you modify it to be part of your system (eg. a Wordpress plugin).
 * 
 * Important: This script must be accessible to everyone, including not logged in users
 *            (so the RESTful API part can be requested from ReducCE server).
 * 
 * Requirements:
 * - PHP 7+ (with MySQLi extension)
 * - MySQL
 * - PHP-JWT 6+ (https://github.com/firebase/php-jwt)
 * 
 * Configuration:
 * 1) Update settings on top of this file
 * 2) Update logged in user ID location in the getLoggedInUserId() function
 * 3) Update SQL query to match your database structure in the getUser() function
 *
 * Installation:
 * 1) Access to this script with the action param set to 'install' (eg.: https://performan-ce.com/autologin-connect.php?action=install)
 * 
 * © Service IT <support@skiloisirsdiffusion.com>
 */

// DISABLE ERRORS
ini_set( 'display_errors', 'off' );

// SETTINGS
define( 'AUTOLOGIN_URI', 'https://billetterie.performan-ce.com/autologin/%token%' ); // must contain %token%
define( 'DB_HOST', 'db5006057994.hosting-data.io' );
define( 'DB_PORT', '3306' );
define( 'DB_USER', 'dbu673826' );
define( 'DB_PASS', 'MsE.Ez6PzZ!n_92&256-951' );
define( 'DB_NAME', 'dbs5073886' );
define('JWT_SECRET_KEY', '?!,jC~p>.d)8K(Yn]rwd?Ii;}m!N[FJ{--,Ag.DyoP+7<2400(yha g:D,eWC$k+');

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/wp-load.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class DB {
    private static $db = null;
    
    /**
     * Get the instanciated MySQLi connection.
     * @return object    The MySQLi object 
     */
    private static function _getDb() {
        if ( self::$db === null ) {
            set_error_handler( function( $errno, $errstr, $errfile, $errline, array $errcontext = [] ) {
                // error was suppressed with the @-operator
                if ( 0 === error_reporting() ) {
                    return false;
                }

                throw new ErrorException( $errstr, 0, $errno, $errfile, $errline );
            });

            try {
                self::$db = new mysqli( DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT );
                self::$db->set_charset( "utf8" );
            } catch ( ErrorException $e ) {
                throw new Exception( $e->getMessage(), 500 );
            }

            restore_error_handler();
        }
        return self::$db;
    }
    
    /**
     * Execute a raw SQL query.
     * @param string    $query    The SQL query
     * @return object|boolean    The query result or false in case of failure
     */
    public static function exec( $query ) {
        $result = self::_getDb()->query( $query );
        if ( self::_getDb()->error ) throw new Exception( 'MySQL error -> ' . self::_getDb()->error, 500 );
        return $result;
    }
    
    /**
     * Fetch single result of a SQL query.
     * @param string    $query    The SQL query
     * @return object|null    The first row of the query result
     */
    public static function fetch( $query ) {
        $result = self::exec( $query );
        if ( $result ) {
            if ($row = $result->fetch_object()) {
                return $row;
            }
        }
        return null;
    }
    
    /**
     * Escape a string to prevent MySQL injections (add quotes and escape its content).
     * @param string    $str    The string
     * @return string    The escaped string
     */
    public static function escape( $str ) {
        return '"' . self::_getDb()->real_escape_string( $str ) . '"';
    }
    
    /**
     * Close the MySQLi connection.
     * @return void
     */
    public static function close() {
        if ( self::$db !== null ) self::$db->close();
    }
}

/**
 * Get the currently logged in user ID.
 * @return string    The user ID
 */
 /* Fan-develop */
function getLoggedInUserId() {
    $user_ID = get_current_user_id();
    return $user_ID; // Edit to fetch the logged in user ID
}


/**
 * Get the user info.
 * @param string    $userId    The user ID
 * @return object    The user info
 */

/* Fan-develop */
function getUser( $userId ) {

    global $current_user;

    // Fetch active user in DB
    // $user = DB::fetch( "SELECT `ID` AS `id`, `user_email` AS `email` FROM `woowp_users` WHERE `woowp_users`.`ID` = " . DB::escape( $userId ) . " AND `woowp_users`.`active` = 1;" ); // Edit to match your DB structure (use aliases "AS" for field names so you don't have to adapt data usage in getUser switch case)

    $current_user = get_user_meta($userId); 

        $user = [
            'id' => $userId,
            'email' => $current_user['billing_email'][0],
            'firstname' => $current_user['first_name'][0],
            'lastname' => $current_user['last_name'][0],
            ];
 
  if ( !$user ) throw new Exception( 'User not found', 404 );

    return $user;
}

/**
 * Generate a JWT token for the user ID.
 * @param string    $userId    The user ID
 * @param string    $type      The token type ('request' or 'access')
 * @param integer   $ttl       (optional) The token TTL in seconds (default = 60s)
 * @return string    The JWT
 */
function encodeToken( $userId, $type, $ttl = 60 ) {
    $payload = array(
        "sub" => $userId,
        "type" => $type,
        "exp" => time() + $ttl
    );
    return JWT::encode( $payload, JWT_SECRET_KEY, 'HS256' );
}

/**
 * Check if the token has already been used.
 * @param string    $jwt    The JWT
 * @return boolean    true if used, false if unused
 */
function isTokenUsed( $jwt ) {
    // Fetch token in DB
    return DB::fetch( "SELECT `token` FROM `used_tokens` WHERE `token` = " . DB::escape( $jwt ) . ";" ) !== null;
}

/**
 * Mark a token as used to prevent further usage.
 * @param string    $jwt    The JWT
 * @return void
 */
function addUsedToken( $jwt ) {
    // Delete expired tokens in DB
    DB::exec( "DELETE FROM `used_tokens` WHERE `expiry` < " . time() . ";" );
    
    // Store used token in DB
    DB::exec( "INSERT INTO `used_tokens` (`token`, `expiry`) VALUES (" . DB::escape( $jwt ) . ", " . ( time() + 86400 ) . ");" ); // keep used token for 24h (must be greater than JWT TTL)
}

/**
 * Check & decode a JWT token.
 * @param string    $jwt    The user ID
 * @param string    $type   The token type ('request' or 'access')
 * @return object    The JWT payload
 */
function decodeToken( $jwt, $type ) {
    try {
        $decoded = JWT::decode( $jwt, new Key( JWT_SECRET_KEY, 'HS256' ) );
        if ( $decoded->type !== $type ) throw new Exception( 'Mismatching type' );
        if ( $decoded->type === 'request' ) {
            if ( isTokenUsed( $jwt ) ) throw new Exception( 'Already used token' );
            addUsedToken( $jwt );
        }
        return $decoded;
    } catch ( Exception $e ) {
        throw new Exception( 'Invalid token -> ' . $e->getMessage(), 403 );
    }
}

/**
 * Extract token from HTTP headers (Authorization: Bearer).
 * @return string|null    The token
 */
function getHeaderToken() {
    $token = null;
    // force headers keys in lowercase for better HTTP2 compatibility
    $headers = array();
    foreach ( getallheaders() as $key => $value ) {
        $headers[strtolower( $key )] = $value;
    }
    if ( !isset( $headers['authorization'] ) && isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
        $headers['authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }
    if ( isset( $headers['authorization'] ) ) {
        $matches = array();
        preg_match( '/^Bearer\s+(.*)$/', $headers['authorization'], $matches );
        if ( isset( $matches[1] ) ) {
            $token = $matches[1];
        }
    }
    if ( empty( $token ) ) throw new Exception( 'Missing token', 401 );

 

   return $token;
}

/**
 * Convert exception to HTTP error code.
 * @param object    $exception    The exception
 * @return string    The HTTP error code
 */
function exceptionToHttpErrorCode( $exception ) {
    $errorCode = '500 Internal Server Error';
    switch( $exception->getCode() ) {
        case 401 :
            $errorCode = '401 Unauthorized';
            break;
        case 403 :
            $errorCode = '403 Forbidden';
            break;
        case 404 :
            $errorCode = '404 Not Found';
            break;
        case 405 :
            $errorCode = '405 Method Not Allowed';
            break;
    }
    return $errorCode;
}

switch( $_GET['action'] ) {
    // *** Initialize database table to store used tokens
    case 'install' :
        header( 'Content-Type: text/html; charset=utf-8' );
        try {
            if (!DB::exec( "CREATE TABLE `used_tokens` (`token` varchar(256) NOT NULL, `expiry` int(11) NOT NULL, UNIQUE KEY `token` (`token`));" )) throw new Exception( 'Installation failed', 500 );
            echo '<p>Installation successfully finished</p>';
        } catch ( Exception $e ) {
            header( 'Content-Type: text/html; charset=utf-8' );
            header( 'HTTP/1.1 ' . exceptionToHttpErrorCode( $e ) );
            echo '<p style="color: red;">Error: ' . $e->getMessage() . '</p>'; 
        }
        break;
    // *** Generate Request Token & redirect to ReducCE
    case 'redirect' :
        try {
            $requestJwt = encodeToken( getLoggedInUserId(), 'request' );
            header( 'Location: ' . str_replace( '%token%', $requestJwt, AUTOLOGIN_URI ) );
        } catch ( Exception $e ) {
            header( 'Content-Type: text/html; charset=utf-8' );
            header( 'HTTP/1.1 ' . exceptionToHttpErrorCode( $e ) );
            echo '<p style="color: red;">Error: ' . $e->getMessage() . '</p>'; 
        }
        break;
    // *** Convert Request Token to Access Token
    case 'authenticate' :
        header( 'Content-Type: application/json; charset=utf-8' );
        try {
            // Check HTTP method
            if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) throw new Exception( 'Invalid method', 405 );
            
            // Decode token
            $decoded = decodeToken( getHeaderToken(), 'request' );

            // Check if user exists
            $user = getUser( $decoded->sub );

            // Generate Access Token
            $accessJwt = encodeToken( $user['id'], 'access' );

            // Return JSON response
            echo json_encode( array(
                "status" => true,
                "userId" => $user['id'],
                "accessToken" => $accessJwt
            ) );

        } catch ( Exception $e ) {
            // Return JSON response
            header( 'HTTP/1.1 ' . exceptionToHttpErrorCode( $e ) );
            echo json_encode( array(
                "status" => false,
                "error" => $e->getMessage()
            ) );
        }
        break;
    // *** Return user info
    case 'getUser' :
        header( 'Content-Type: application/json; charset=utf-8' );
        try {
            // Check HTTP method
            if ( $_SERVER['REQUEST_METHOD'] !== 'GET' ) throw new Exception( 'Invalid method', 405 );
            
            // Get URI params
            $id = $_GET['id'];
                 
            // Decode token
            $decoded = decodeToken( getHeaderToken(), 'access' );
            
            // Check if token matches requested user ID
            if ( (string)$decoded->sub !== (string)$id ) throw new Exception( 'Inaccessible resource', 403 );
                
            // Get user info
            $user = getUser( $id );
            
            // Fan-develop 
            // Return JSON response
            echo json_encode( array(
                "status" => true,
                "id" => $id,
                "email" => $user['email'],
                "firstname" => $user['firstname'],
                "lastname" => $user['lastname']
            ) );
        } catch ( Exception $e ) {
            // Return JSON response
            header( 'HTTP/1.1 ' . exceptionToHttpErrorCode( $e ) );
            echo json_encode( array(
                "status" => false,
                "error" => $e->getMessage()
            ) );
        }
        break;
    // Unknown action
    default :
        header( 'Content-Type: text/html; charset=utf-8' );
        header( 'HTTP/1.1 404 Not Found' );
        echo '<p>Unknown action</p>';
}

// Close DB connection
DB::close();
