package user;

public class UserDao {

    public User getUserByUserName(String userName) {
        return switch (userName) {
            case "user" -> new User("user", "Anonymous User");
            case "alice" -> new User("alice", "Alice Smith");
            case "bob" -> new User("bob", "Bob Jones");
            default -> null;
        };
    }
}
