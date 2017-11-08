package user;

public class UserDao {

    public User getUserByUserName(String userName) {
        switch (userName) {
            case "user": return new User("user", "Anonymous User");
            case "jill": return new User("jill", "Jill Smith");
            default: return null;
        }
    }


}
