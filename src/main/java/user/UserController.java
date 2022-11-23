package user;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;
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

        count = count instanceof Integer
                ? (Integer) count + 1
                : 0;

        session.setAttribute("count", count);

        return String.valueOf(count);
    }

    @GetMapping("/api/home")
    public String home() {
        return "Api home url";
    }

    @GetMapping("/api/info")
    public String info(Principal principal) {
        String user = principal != null ? principal.getName() : "";

        return "Current user: " + user;
    }

    @GetMapping("/api/admin/info")
    public String adminInfo(Principal principal) {
        return "Admin user info: " + principal.getName();
    }

    @PreAuthorize("#userName == authentication.name")
    @GetMapping("/api/users/{userName}")
    public User getUserByName(@PathVariable String userName) {
        return new UserDao().getUserByUserName(userName);
    }

}