use futures_util::StreamExt as _;

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
enum Streams {
    Requests,
    Timer,
}

#[derive(Debug)]
enum Action {
    Set(std::time::Duration),
    Clear,
}

pub struct Timeout {
    req_w: tokio::sync::mpsc::UnboundedSender<Action>,
    // When the running timer fires, so a re-exec can hand the rest of it
    // to the new agent (`remaining`).
    deadline: std::sync::Mutex<Option<std::time::Instant>>,
}

impl Timeout {
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (req_w, req_r) = tokio::sync::mpsc::unbounded_channel();
        let (timer_w, timer_r) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            enum Event {
                Request(Action),
                Timer,
            }
            let mut stream = tokio_stream::StreamMap::new();
            stream.insert(
                Streams::Requests,
                tokio_stream::wrappers::UnboundedReceiverStream::new(req_r)
                    .map(Event::Request)
                    .boxed(),
            );
            while let Some(event) = stream.next().await {
                match event {
                    (_, Event::Request(Action::Set(dur))) => {
                        stream.insert(
                            Streams::Timer,
                            futures_util::stream::once(tokio::time::sleep(
                                dur,
                            ))
                            .map(|()| Event::Timer)
                            .boxed(),
                        );
                    }
                    (_, Event::Request(Action::Clear)) => {
                        stream.remove(&Streams::Timer);
                    }
                    (_, Event::Timer) => {
                        timer_w.send(()).unwrap();
                    }
                }
            }
        });
        (
            Self {
                req_w,
                deadline: std::sync::Mutex::new(None),
            },
            timer_r,
        )
    }

    pub fn set(&self, dur: std::time::Duration) {
        *self.deadline.lock().unwrap() =
            std::time::Instant::now().checked_add(dur);
        self.req_w.send(Action::Set(dur)).unwrap();
    }

    pub fn clear(&self) {
        *self.deadline.lock().unwrap() = None;
        self.req_w.send(Action::Clear).unwrap();
    }

    // The time left until the timer fires, or `None` when none is running.
    pub fn remaining(&self) -> Option<std::time::Duration> {
        self.deadline.lock().unwrap().map(|deadline| {
            deadline.saturating_duration_since(std::time::Instant::now())
        })
    }
}
