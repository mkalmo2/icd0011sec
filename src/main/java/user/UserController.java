package user;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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

        if (count != null && count instanceof Integer) {
            count = (Integer) count + 1;
        } else {
            count = 0;
        }

        session.setAttribute("count", count);

        return String.valueOf(count);
    }

    @GetMapping("/api/info")
    public String info(Principal principal) {
        return "Current user: " + principal.getName();
    }

    @GetMapping("/api/users/{userName}")
    @PreAuthorize("#userName == authentication.name")
    public User getUserByName(@PathVariable String userName,
                              Authentication authentication) {

        System.out.println("userName: " + userName);
        System.out.println("authentication.name: " + authentication.getName());
        System.out.println("auth: " + authentication.getAuthorities());

        return new UserDao().getUserByUserName(userName);
    }


}