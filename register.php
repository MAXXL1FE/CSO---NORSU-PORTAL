<?php
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/config/db.php';

if (is_logged_in()) {
    redirect_to_dashboard();
}

$errors = [];
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $student_id = clean($_POST['student_id']);
    $first_name  = clean($_POST['first_name']);
    $middle_name = clean($_POST['middle_name'] ?? '');
    $last_name   = clean($_POST['last_name']);
    $suffix      = clean($_POST['suffix'] ?? '');
    $email      = clean($_POST['email']);
    $course     = clean($_POST['course']);
    $year_level = clean($_POST['year_level']);
    $password   = $_POST['password'];
    $confirm    = $_POST['confirm_password'];

    if (empty($student_id) || empty($first_name) || empty($last_name) || empty($email) || empty($course) || empty($year_level) || empty($password)) {
        $errors[] = 'All fields are required.';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }
    if (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters.';
    }
    if ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    }

    if (empty($errors)) {
        $check = $conn->prepare("SELECT user_id FROM users WHERE student_id = ? OR email = ?");
        $check->bind_param('ss', $student_id, $email);
        $check->execute();
        $check->store_result();

        if ($check->num_rows > 0) {
            $errors[] = 'An account with this Student ID or email already exists.';
        } else {
            $hashed = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO users (student_id, first_name, middle_name, last_name, suffix, email, password, course, year_level, role, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'member', 'active')");
            $stmt->bind_param('sssssssss', $student_id, $first_name, $middle_name, $last_name, $suffix, $email, $hashed, $course, $year_level);

            if ($stmt->execute()) {
                $success = true;
            } else {
                $errors[] = 'Registration failed. Please try again.';
            }
            $stmt->close();
        }
        $check->close();
    }
}

$page_title = 'Register';
require_once __DIR__ . '/includes/header.php';
?>

<section class="section auth-section">
    <div class="container narrow">
        <h2>Create Your CSO Account</h2>

        <?php if ($success): ?>
            <div class="alert alert-success">
                Registration successful! You can now <a href="<?php echo BASE_URL; ?>/login.php">log in</a>.
            </div>
        <?php else: ?>
            <?php if (!empty($errors)): ?>
                <div class="alert alert-error">
                    <ul>
                        <?php foreach ($errors as $err): ?>
                            <li><?php echo htmlspecialchars($err); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <form method="POST" action="<?php echo BASE_URL; ?>/register.php" class="form">
                <?php echo csrf_field(); ?>
                <div class="form-row">
                    <label for="student_id">Student ID</label>
                    <input type="text" id="student_id" name="student_id" placeholder="e.g. 2026-001" value="<?php echo isset($_POST['student_id']) ? htmlspecialchars($_POST['student_id']) : ''; ?>" required>
                </div>
                <div class="form-row form-row-split">
                    <div>
                        <label for="first_name">First Name</label>
                        <input type="text" id="first_name" name="first_name" placeholder="e.g. Cristianery" value="<?php echo isset($_POST['first_name']) ? htmlspecialchars($_POST['first_name']) : ''; ?>" required>
                    </div>
                    <div>
                        <label for="middle_name">Middle Name <span class="muted" style="font-weight:400;">(optional)</span></label>
                        <input type="text" id="middle_name" name="middle_name" value="<?php echo isset($_POST['middle_name']) ? htmlspecialchars($_POST['middle_name']) : ''; ?>">
                    </div>
                    <div>
                        <label for="last_name">Last Name</label>
                        <input type="text" id="last_name" name="last_name" placeholder="e.g. Khim" value="<?php echo isset($_POST['last_name']) ? htmlspecialchars($_POST['last_name']) : ''; ?>" required>
                    </div>
                    <div>
                        <label for="suffix">Suffix <span class="muted" style="font-weight:400;">(optional, e.g. Jr., Sr., II, III)</span></label>
                        <input type="text" id="suffix" name="suffix" placeholder="e.g. Jr." value="<?php echo isset($_POST['suffix']) ? htmlspecialchars($_POST['suffix']) : ''; ?>">
                    </div>
                </div>
                <div class="form-row">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required>
                </div>
                <div class="form-row form-row-split">
                    <div>
                        <label for="course">Course</label>
                        <?php
                            $courses = ['BS Computer Science', 'BS Information Technology', 'BS Information Systems'];
                            $posted_course = isset($_POST['course']) ? $_POST['course'] : '';
                            $is_other = $posted_course !== '' && !in_array($posted_course, $courses, true);
                        ?>
                        <select id="course" name="course" onchange="document.getElementById('course_other').style.display = (this.value === 'Other') ? 'block' : 'none';" required>
                            <option value="">Select</option>
                            <?php foreach ($courses as $c): ?>
                                <option value="<?php echo $c; ?>" <?php echo ($posted_course === $c) ? 'selected' : ''; ?>><?php echo $c; ?></option>
                            <?php endforeach; ?>
                            <option value="Other" <?php echo $is_other ? 'selected' : ''; ?>>Other</option>
                        </select>
                        <input type="text" id="course_other" placeholder="Please specify your course" value="<?php echo $is_other ? htmlspecialchars($posted_course) : ''; ?>" style="display: <?php echo $is_other ? 'block' : 'none'; ?>; margin-top: 8px;" oninput="document.getElementById('course').querySelector('option[value=\'Other\']').value = this.value || 'Other';">
                    </div>
                    <div>
                        <label for="year_level">Year Level</label>
                        <select id="year_level" name="year_level" required>
                            <option value="">Select</option>
                            <?php foreach (['1st Year', '2nd Year', '3rd Year', '4th Year'] as $yr): ?>
                                <option value="<?php echo $yr; ?>" <?php echo (isset($_POST['year_level']) && $_POST['year_level'] === $yr) ? 'selected' : ''; ?>><?php echo $yr; ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="form-row form-row-split">
                    <div>
                        <label for="password">Password</label>
                        <div class="pw-wrap">
                            <input type="password" id="password" name="password" minlength="8" required>
                            <button type="button" class="pw-toggle" aria-label="Show password">👁</button>
                        </div>
                    </div>
                    <div>
                        <label for="confirm_password">Confirm Password</label>
                        <div class="pw-wrap">
                            <input type="password" id="confirm_password" name="confirm_password" minlength="8" required>
                            <button type="button" class="pw-toggle" aria-label="Show password">👁</button>
                        </div>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Register</button>
                <p class="form-footnote">Already have an account? <a href="<?php echo BASE_URL; ?>/login.php">Log in</a></p>
            </form>
        <?php endif; ?>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
