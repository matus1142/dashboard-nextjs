import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
        return user.rows[0];
    } catch (error) {
        console.error('Failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [
        Credentials({
            async authorize(credentials) {
                // use zod library to validate credential
                const parsedCredentials = z
                    .object({ email: z.string().email(), password: z.string().min(6) })
                    .safeParse(credentials);

                // if credentials are valid with format
                if (parsedCredentials.success) {

                    // destructure credentials
                    const { email, password } = parsedCredentials.data;
                    
                    // use email to fetch user from database
                    const user = await getUser(email);

                    // if user not found then return null
                    if (!user) return null;

                    // if user found then compare passwords by use bcrypt library
                    // password comes from user input and user.password comes from database
                    const passwordsMatch = await bcrypt.compare(password, user.password);

                    // if passwords match then return user
                    if (passwordsMatch) return user;

                }
                console.log('Invalid credentials');
                return null;
            },
        }),
    ],
});