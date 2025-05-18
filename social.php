<?php
session_start();


$host = 'localhost';
$dbname = 'social_platform';
$dbuser = 'root';
$dbpass = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $dbuser, $dbpass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}


function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getUserById($id) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function getAllPosts() {
    global $pdo;
    $stmt = $pdo->query("SELECT posts.*, users.username 
                         FROM posts 
                         JOIN users ON posts.user_id = users.id 
                         ORDER BY created_at DESC");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getPostById($id) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT posts.*, users.username 
                           FROM posts 
                           JOIN users ON posts.user_id = users.id 
                           WHERE posts.id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function getCommentsByPostId($post_id) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT comments.*, users.username 
                           FROM comments 
                           JOIN users ON comments.user_id = users.id 
                           WHERE post_id = ? 
                           ORDER BY created_at ASC");
    $stmt->execute([$post_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'register':
                $username = trim($_POST['username']);
                $password = trim($_POST['password']);
                
                if (empty($username) || empty($password)) {
                    $error = "Användarnamn och lösenord får inte vara tomma.";
                } else {
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                    $stmt->execute([$username]);
                    
                    if ($stmt->fetch()) {
                        $error = "Användarnamnet är upptaget. Vänligen välj ett annat.";
                    } else {
                        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                        $stmt->execute([$username, $hashedPassword]);
                        
                        $_SESSION['user_id'] = $pdo->lastInsertId();
                        $_SESSION['username'] = $username;
                        header('Location: social.php');
                        exit;
                    }
                }
                break;
                
            case 'login':
                $username = trim($_POST['username']);
                $password = trim($_POST['password']);
                
                $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch();
                
                if ($user && password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    header('Location: social.php');
                    exit;
                } else {
                    $error = "Fel användarnamn eller lösenord.";
                }
                break;
                
            case 'create_post':
                if (!isLoggedIn()) {
                    header('Location: social.php?page=login');
                    exit;
                }
                
                $title = trim($_POST['title']);
                $content = trim($_POST['content']);
                
                if (empty($title) || empty($content)) {
                    $post_error = "Titel och innehåll får inte vara tomma.";
                } else {
                    $stmt = $pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
                    $stmt->execute([$_SESSION['user_id'], $title, $content]);
                    header('Location: social.php');
                    exit;
                }
                break;
                
            case 'add_comment':
                if (!isLoggedIn()) {
                    header('Location: social.php?page=login');
                    exit;
                }
                
                $post_id = $_POST['post_id'];
                $content = trim($_POST['content']);
                
                if (!empty($content)) {
                    $stmt = $pdo->prepare("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)");
                    $stmt->execute([$post_id, $_SESSION['user_id'], $content]);
                    header("Location: social.php?page=view_post&id=$post_id");
                    exit;
                }
                break;
        }
    }
}


if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: social.php');
    exit;
}


$page = isset($_GET['page']) ? $_GET['page'] : 'home';
?>
<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Social Plattform</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <h1>Vår Sociala Plattform</h1>
        <nav>
            <?php if (isLoggedIn()): ?>
                <a href="social.php">Hem</a>
                <a href="social.php?page=create_post">Skapa Inlägg</a>
                <a href="social.php?logout=1">Logga ut</a>
                <span>Välkommen, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
            <?php else: ?>
                <a href="social.php">Hem</a>
                <a href="social.php?page=login">Logga in</a>
                <a href="social.php?page=register">Registrera</a>
            <?php endif; ?>
        </nav>
    </header>
    <main>
        <?php
        switch ($page) {
            case 'register':
                ?>
                <h2>Registrera Konto</h2>
                <?php if (isset($error)): ?>
                    <div class="error"><?php echo $error; ?></div>
                <?php endif; ?>
                <form method="post">
                    <input type="hidden" name="action" value="register">
                    <div>
                        <label for="username">Användarnamn:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div>
                        <label for="password">Lösenord:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit">Registrera</button>
                </form>
                <p>Redan medlem? <a href="social.php?page=login">Logga in här</a></p>
                <?php
                break;
                
            case 'login':
                ?>
                <h2>Logga In</h2>
                <?php if (isset($error)): ?>
                    <div class="error"><?php echo $error; ?></div>
                <?php endif; ?>
                <form method="post">
                    <input type="hidden" name="action" value="login">
                    <div>
                        <label for="username">Användarnamn:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div>
                        <label for="password">Lösenord:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit">Logga In</button>
                </form>
                <p>Inte medlem än? <a href="social.php?page=register">Registrera dig här</a></p>
                <?php
                break;
                
            case 'create_post':
                if (!isLoggedIn()) {
                    header('Location: social.php?page=login');
                    exit;
                }
                ?>
                <h2>Skapa Nytt Inlägg</h2>
                <?php if (isset($post_error)): ?>
                    <div class="error"><?php echo $post_error; ?></div>
                <?php endif; ?>
                <form method="post">
                    <input type="hidden" name="action" value="create_post">
                    <div>
                        <label for="title">Titel:</label>
                        <input type="text" id="title" name="title" required>
                    </div>
                    <div>
                        <label for="content">Innehåll:</label>
                        <textarea id="content" name="content" rows="5" required></textarea>
                    </div>
                    <button type="submit">Publicera</button>
                </form>
                <?php
                break;
                
            case 'view_post':
                if (!isset($_GET['id'])) {
                    header('Location: social.php');
                    exit;
                }
                
                $post_id = $_GET['id'];
                $post = getPostById($post_id);
                
                if (!$post) {
                    header('Location: social.php');
                    exit;
                }
                ?>
                <article class="post">
                    <h2><?php echo htmlspecialchars($post['title']); ?></h2>
                    <p><?php echo nl2br(htmlspecialchars($post['content'])); ?></p>
                    <div class="post-meta">
                        <span>Skapad av: <?php echo htmlspecialchars($post['username']); ?></span>
                        <span>Datum: <?php echo date('Y-m-d H:i', strtotime($post['created_at'])); ?></span>
                    </div>
                </article>
                
                <section class="comments">
                    <h3>Kommentarer</h3>
                    
                    <?php if (isLoggedIn()): ?>
                        <form method="post" class="comment-form">
                            <input type="hidden" name="action" value="add_comment">
                            <input type="hidden" name="post_id" value="<?php echo $post_id; ?>">
                            <textarea name="content" placeholder="Skriv din kommentar här..." required></textarea>
                            <button type="submit">Skicka kommentar</button>
                        </form>
                    <?php else: ?>
                        <p><a href="social.php?page=login">Logga in</a> för att kommentera.</p>
                    <?php endif; ?>
                    
                    <?php
                    $comments = getCommentsByPostId($post_id);
                    foreach ($comments as $comment):
                    ?>
                        <div class="comment">
                            <p><?php echo nl2br(htmlspecialchars($comment['content'])); ?></p>
                            <div class="comment-meta">
                                <span>Av: <?php echo htmlspecialchars($comment['username']); ?></span>
                                <span>Datum: <?php echo date('Y-m-d H:i', strtotime($comment['created_at'])); ?></span>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </section>
                <?php
                break;
                
            default: 
                ?>
                <h2>Alla Inlägg</h2>
                
                <?php if (isLoggedIn()): ?>
                    <p><a href="social.php?page=create_post" class="button">Skapa nytt inlägg</a></p>
                <?php endif; ?>
                
                <?php
                $posts = getAllPosts();
                foreach ($posts as $post):
                ?>
                    <article class="post">
                        <h3><a href="social.php?page=view_post&id=<?php echo $post['id']; ?>"><?php echo htmlspecialchars($post['title']); ?></a></h3>
                        <p><?php echo nl2br(htmlspecialchars($post['content'])); ?></p>
                        <div class="post-meta">
                            <span>Skapad av: <?php echo htmlspecialchars($post['username']); ?></span>
                            <span>Datum: <?php echo date('Y-m-d H:i', strtotime($post['created_at'])); ?></span>
                        </div>
                    </article>
                <?php endforeach; ?>
                <?php
                break;
        }
        ?>
    </main>
    <footer>
        <p>&copy; <?php echo date('Y'); ?> Vår Sociala Plattform</p>
    </footer>
</body>
</html>