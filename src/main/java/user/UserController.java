package user;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
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

    @GetMapping("/api/hello")
    public String hello() {
        return "Hello!";
    }

    @GetMapping("/api/info")
    public String info(Principal principal) {
        return "Current user: " + principal.getName();
    }

    @GetMapping("/api/users/{userName}")
    @PreAuthorize("#userName == authentication.name")
    public User getUserByName(@PathVariable String userName) {
        return new UserDao().getUserByUserName(userName);
    }

}