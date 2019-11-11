package user;

public class UserDao {

    public User getUserByUserName(String userName) {
        switch (userName) {
            case "user": return new User("user", "Anonymous User");
            case "alice": return new User("alice", "Alice Smith");
            case "bob": return new User("bob", "Bob Jones");
            default: return null;
        }
    }


}
