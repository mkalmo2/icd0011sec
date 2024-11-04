package user;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserController {

    @GetMapping("/")
    public String frontPage() {
        return "Front page!";
    }

    @GetMapping("/count")
    public String counter(HttpSession session) {

        Object count = session.getAttribute("count");

        count = count instanceof Integer i
                ? i + 1
                : 0;

        session.setAttribute("count", count);

        return String.valueOf(count);
    }

    @GetMapping("/home")
    public String home() {
        return "Api home url";
    }

    @GetMapping("/info")
    public String info(Principal principal) {
        String user = principal != null ? principal.getName() : "";

        return "Current user: " + user;
    }

    @GetMapping("/admin/info")
    public String adminInfo(Principal principal) {
        return "Admin user info: " + principal.getName();
    }

    @GetMapping("/users/{username}")
    public User getUserByName(@PathVariable("username") String username) {
        return new UserDao().getUserByUserName(username);
    }
}