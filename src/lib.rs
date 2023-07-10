use std::{collections::HashSet, error::{self, Error}, fmt::Display};

struct DiffieHellman {
    /// large prime number
    p: u32, 
    /// a primitive root of P 
    g: u32, 
    /// the result of person A's equation
    /// person B uses this to calculate shared secret
    x: Option<u32>,
    /// the result of person B's equation
    /// person A uses this to calculate shared secret
    y: Option<u32>
}

impl DiffieHellman {

    pub fn new(p: u32, g: u32) -> Self {
        Self {
            p,
            g, 
            x: None, 
            y: None,
        }
    }
    
    /// check if p is a prime number 
    pub fn is_prime(number: &u32) -> Result<(), Box<dyn error::Error>> {
        match number {
            0 => return Err(Box::new(DHError::InvalidP)),
            1 => return Err(Box::new(DHError::InvalidP)),
            2 => return Ok(()),
            _ => {  
                let mut i = 2; 
                while i*i <= *number {
                    if number % i == 0 {
                        return Err(Box::new(DHError::InvalidP));
                    }
                    i += 1; 
                }
                return Ok(());
            },
        }
    }

    /// check if g is a primitive root of p 
    pub fn is_primitive_root(prime: &u32, g: &u32) -> Result<(), Box<dyn error::Error>> {
        // create powers of {p_root} mod {prime}
        // Euler Phi Function
        let mut res: HashSet<_> = HashSet::new(); 
        for i in 1..*prime {
            let value: u32 = i.pow(*g) % prime;
            match res.contains(&value) {
                false => res.insert(value),
                true => {return Err(Box::new(DHError::InvalidG));}  
            };    
        }
        return Ok(()); 
    }

    /// ensures the valid setup to a Diffie Hellman key exchange
    /// bubbles up errors from primtive root fn and prime number fn
    pub fn is_valid(&self) -> Result<(), Box<dyn error::Error>> {
        DiffieHellman::is_prime(&self.p)?;
        DiffieHellman::is_primitive_root( &self.p, &self.g)?;
        Ok(())
    }

    /// compute the public value for person A using their own secret, outputs a number usable by person B to calculate the shared secret 
    pub fn calculate_pub_x(mut self, secret: u32) -> Self {
        self.x = Some(self.g.pow(secret) % self.p);
        self
    } 
    
    /// compute the public value for person B using their own secret, outputs a number usable by person A to calculate the shared secret 
    pub fn calculate_pub_y(mut self, secret: u32) -> Self {
        self.y = Some(self.g.pow(secret) % self.p);
        self
    } 

    /// compute the shared secret for person A using the public value calculated by person B (y)
    /// hould always match the output of shared_secret_b 
    pub fn shared_secret_a(&self, secret: u32) -> Result<u32, Box<dyn error::Error>> {
        match self.y {
            Some(y) => return Ok(y.pow(secret) % self.p),
            None => return Err(Box::new(DHError::SecretNotComputed)),
        }
    }
    
    /// compute the shared secret for person B using the public value calculated by person A (x)
    /// should always match the output of shared_secret_a 
    pub fn shared_secret_b(&self, secret: u32) -> Result<u32, Box<dyn error::Error>> {
        match self.x {
            Some(x) => return Ok(x.pow(secret) % self.p),
            None => return Err(Box::new(DHError::SecretNotComputed)),
        }
    }
}   
#[derive(Debug)]
enum DHError {
    SecretNotComputed,
    InvalidP,
    InvalidG
}

impl Display for DHError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecretNotComputed => write!(f, "Pub Value not yet computed with P and G values"),
            Self::InvalidP => write!(f, "Invalid value of P, not prime"),
            Self::InvalidG => write!(f, "Invalid value of G, not primitive root"),
        }
    }
}

impl Error for DHError {}