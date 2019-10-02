from ryu.controller import ofp_event, event

# this api is used to send and receive event between different ryu application 
class EventMessage(event.EventBase):
    def __init__(self, message=[]):
        super(EventMessage, self).__init__()
        self.message = message
